package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/pkg/logger"
)

// procKillGrace bounds how long Wait() blocks on a tool's output pipes AFTER the
// context is cancelled and the process group has been signalled. If a stray
// descendant still holds a pipe open past this, the exec package force-closes
// the pipes so Wait() returns instead of hanging.
const procKillGrace = 10 * time.Second

// hardenProc makes a subprocess killable as a whole PROCESS GROUP and bounds how
// long Wait blocks on its output pipes. Without this, exec.CommandContext kills
// only the tool's OWN pid on context cancellation (e.g. an operator skipping the
// network brute phase) — worker children the tool spawned (hydra's per-target
// workers, feroxbuster/dirsearch threads) survive and keep the stdout/stderr
// pipes open, so the pipe-reader goroutines never see EOF and Wait() blocks
// forever. That is the class of bug where skipping an external-tool phase
// leaves its task stuck with no further output.
// Setpgid puts the tool in its own group; Cancel SIGKILLs the whole group; and
// WaitDelay force-closes the pipes if any descendant still lingers.
func hardenProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid signals the ENTIRE process group (see Setpgid above).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = procKillGrace
}

type Executor struct {
	cfg         *config.Config
	logger      *logger.Logger
	semaphore   chan struct{}
	mu          sync.Mutex
	activeProcs map[string]map[*exec.Cmd]struct{}
	toolFree    bool
}

// NewToolFreeExecutor is the deterministic counterpart used by tests and
// embedders that explicitly want Reconner's native fallbacks. It prevents a
// developer's locally installed httpx/katana/etc. from silently changing an
// otherwise tool-free test into a slow external integration test.
func NewToolFreeExecutor(cfg *config.Config, log *logger.Logger) *Executor {
	e := NewExecutor(cfg, log)
	e.toolFree = true
	return e
}

func NewExecutor(cfg *config.Config, log *logger.Logger) *Executor {
	maxExecutions := cfg.Limits.MaxToolExecutions
	if maxExecutions <= 0 {
		// A zero-capacity channel blocks forever on the first external command.
		// DefaultConfig normally supplies this value, but tests, embedders and
		// partially migrated configs can legitimately construct a sparse Config.
		maxExecutions = 1
	}
	return &Executor{
		cfg:         cfg,
		logger:      log,
		semaphore:   make(chan struct{}, maxExecutions),
		activeProcs: make(map[string]map[*exec.Cmd]struct{}),
	}
}

const (
	maxToolStdoutLineBytes = 16 << 20 // 16 MiB
	maxToolStderrLineBytes = 1 << 20  // 1 MiB
)

func (e *Executor) registerActiveProc(taskID string, cmd *exec.Cmd) {
	e.mu.Lock()
	procs := e.activeProcs[taskID]
	if procs == nil {
		procs = make(map[*exec.Cmd]struct{})
		e.activeProcs[taskID] = procs
	}
	procs[cmd] = struct{}{}
	e.mu.Unlock()
}

func (e *Executor) unregisterActiveProc(taskID string, cmd *exec.Cmd) {
	e.mu.Lock()
	if procs := e.activeProcs[taskID]; procs != nil {
		delete(procs, cmd)
		if len(procs) == 0 {
			delete(e.activeProcs, taskID)
		}
	}
	e.mu.Unlock()
}

// scanStreamLines reads newline-delimited lines from r using a 64 KiB reader.
// Lines up to maxLineBytes are delivered via onLine (with trailing \r?\n
// stripped, including a final line without a trailing newline). Any single
// line exceeding maxLineBytes is drained to the next newline (or EOF), reported
// via onOversized, and scanning continues on subsequent lines without stopping
// or blocking the pipe writer.
func scanStreamLines(r io.Reader, maxLineBytes int, onLine func(string), onOversized func(int)) error {
	if maxLineBytes <= 0 {
		maxLineBytes = 64 * 1024
	}
	br := bufio.NewReaderSize(r, 64*1024)
	var buf []byte
	oversized := false
	droppedBytes := 0

	trimEOL := func(b []byte) []byte {
		if len(b) > 0 && b[len(b)-1] == '\n' {
			b = b[:len(b)-1]
		}
		if len(b) > 0 && b[len(b)-1] == '\r' {
			b = b[:len(b)-1]
		}
		return b
	}

	resetBuf := func() {
		if cap(buf) > 256*1024 {
			buf = nil
		} else {
			buf = buf[:0]
		}
	}

	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			if oversized {
				droppedBytes += len(chunk)
			} else if len(buf) == 0 && err == nil {
				trimmed := trimEOL(chunk)
				if len(trimmed) > maxLineBytes {
					if onOversized != nil {
						onOversized(len(chunk))
					}
					continue
				}
				if onLine != nil {
					onLine(string(trimmed))
				}
				continue
			} else {
				if len(buf)+len(chunk) > maxLineBytes {
					if err != bufio.ErrBufferFull {
						candidate := append(buf, chunk...)
						trimmed := trimEOL(candidate)
						if len(trimmed) <= maxLineBytes {
							if onLine != nil {
								onLine(string(trimmed))
							}
							resetBuf()
							if err == io.EOF {
								return nil
							}
							if err != nil {
								return err
							}
							continue
						}
					}
					oversized = true
					droppedBytes = len(buf) + len(chunk)
					buf = nil
				} else {
					buf = append(buf, chunk...)
				}
			}
		}

		if err == bufio.ErrBufferFull {
			continue
		}

		if oversized {
			if onOversized != nil {
				onOversized(droppedBytes)
			}
			oversized = false
			droppedBytes = 0
			buf = nil
		} else if len(buf) > 0 {
			if onLine != nil {
				onLine(string(trimEOL(buf)))
			}
			resetBuf()
		}

		if err == nil {
			continue
		}
		if err == io.EOF {
			return nil
		}
		return err
	}
}

type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// toolEnv returns the EXTRA environment variables a tool needs. The value is
// read at RUN time from the live config, so a key saved in the UI works on the
// next run without restarting the service.
//
// The projectdiscovery tools read their shared account key from PDCP_API_KEY:
// chaos needs it, subfinder accepts it for the paid provider sources.
func (e *Executor) toolEnv(name string) []string {
	if e.cfg == nil {
		return nil
	}
	key := strings.TrimSpace(e.cfg.ChaosAPIKey)
	if key == "" {
		return nil
	}
	switch name {
	case "chaos", "subfinder":
		return []string{"PDCP_API_KEY=" + key}
	}
	return nil
}

// cmdEnv builds the environment for a tool process: the parent environment,
// HOME, the extended PATH and any tool-specific variables.
func (e *Executor) cmdEnv(name string) []string {
	env := append(os.Environ(), "HOME="+os.Getenv("HOME"), "PATH="+e.extendedPath())
	return append(env, e.toolEnv(name)...)
}

type LineCallback func(line string)

// validateToolName keeps callers on Reconner's curated executable search path.
// Tool arguments may contain arbitrary target data, but the executable itself
// must be a bare ASCII filename: never a relative/absolute path or shell text.
func validateToolName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("invalid external tool name %q", name)
	}
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '+' {
			continue
		}
		return fmt.Errorf("invalid external tool name %q", name)
	}
	return nil
}

func (e *Executor) RunWithCallback(ctx context.Context, taskID string, callback LineCallback, name string, args ...string) error {
	if err := validateToolName(name); err != nil {
		return err
	}
	if e.toolFree {
		return fmt.Errorf("external tool %s disabled", name)
	}
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}

	toolPath := e.findTool(name)
	cmd := exec.CommandContext(ctx, toolPath, args...) // #nosec G204,G702 -- toolPath derives from a validated bare executable name and fixed search directories
	cmd.Env = e.cmdEnv(name)
	hardenProc(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}

	e.registerActiveProc(taskID, cmd)
	defer e.unregisterActiveProc(taskID, cmd)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := scanStreamLines(stdout, maxToolStdoutLineBytes, func(line string) {
			if line != "" && callback != nil {
				e.safeCallback(name, callback, line)
			}
		}, func(dropped int) {
			if e.logger != nil {
				e.logger.Warn("Dropped oversized tool stdout line", "tool", name, "bytes", dropped)
			}
		}); err != nil && e.logger != nil {
			e.logger.Warn("Tool stdout stream read error", "tool", name, "error", err)
		}
	}()

	// Keep a bounded tail of stderr so a non-zero exit can report WHY, not just
	// "exit status N". A tool that rejects a flag (httpx exit status 2) or dies on
	// startup writes the reason here; without it the operator only sees the code
	// and a scan can silently collapse to zero results.
	var errTail stderrTail
	go func() {
		defer wg.Done()
		if err := scanStreamLines(stderr, maxToolStderrLineBytes, func(line string) {
			if e.logger != nil {
				e.logger.Debug("Tool stderr", "tool", name, "line", line)
			}
			errTail.add(line)
		}, func(dropped int) {
			if e.logger != nil {
				e.logger.Warn("Dropped oversized tool stderr line", "tool", name, "bytes", dropped)
			}
		}); err != nil && e.logger != nil {
			e.logger.Warn("Tool stderr stream read error", "tool", name, "error", err)
		}
	}()
	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if tail := errTail.string(); tail != "" {
			return fmt.Errorf("%w: %s", err, tail)
		}
		return err
	}
	return nil
}

// stderrTail keeps the last few non-empty stderr lines of a streamed tool run so
// a failure can surface the tool's own message. Bounded so a chatty tool cannot
// grow it without limit.
type stderrTail struct {
	lines []string
}

func (t *stderrTail) add(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	const maxLines = 5
	t.lines = append(t.lines, line)
	if len(t.lines) > maxLines {
		t.lines = t.lines[len(t.lines)-maxLines:]
	}
}

func (t *stderrTail) string() string {
	out := strings.TrimSpace(strings.Join(t.lines, "; "))
	const maxLen = 400
	if len(out) > maxLen {
		out = out[:maxLen] + "…"
	}
	return out
}

// safeCallback runs a per-line callback with panic recovery. A callback panics
// in this reader goroutine — not under the scheduler's recover — so without this
// a single malformed tool line could crash the whole process.
func (e *Executor) safeCallback(tool string, cb LineCallback, line string) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("Recovered from tool callback panic", "tool", tool, "panic", r)
		}
	}()
	cb(line)
}

func (e *Executor) Run(ctx context.Context, name string, args ...string) (*ExecResult, error) {
	if err := validateToolName(name); err != nil {
		return nil, err
	}
	if e.toolFree {
		return nil, fmt.Errorf("external tool %s disabled", name)
	}
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	start := time.Now()
	toolPath := e.findTool(name)
	cmd := exec.CommandContext(ctx, toolPath, args...) // #nosec G204,G702 -- toolPath derives from a validated bare executable name and fixed search directories
	cmd.Env = e.cmdEnv(name)
	hardenProc(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return result, fmt.Errorf("run %s: %w", name, err)
		}
	}

	return result, nil
}

func (e *Executor) KillTask(taskID string) {
	e.mu.Lock()
	var cmds []*exec.Cmd
	for cmd := range e.activeProcs[taskID] {
		cmds = append(cmds, cmd)
	}
	e.mu.Unlock()

	for _, cmd := range cmds {
		if cmd == nil || cmd.Process == nil {
			continue
		}
		if cmd.Cancel != nil {
			_ = cmd.Cancel()
			continue
		}
		_ = cmd.Process.Kill()
	}
}

func (e *Executor) IsToolAvailable(name string) bool {
	if e.toolFree || validateToolName(name) != nil {
		return false
	}
	path := e.findTool(name)
	if path == name {
		_, err := exec.LookPath(name)
		return err == nil
	}
	_, err := os.Stat(path)
	return err == nil
}

func (e *Executor) findTool(name string) string {
	localPath := filepath.Join(e.cfg.ToolsDir, name) // #nosec G703 -- name is validated by every public executor entrypoint
	if _, err := os.Stat(localPath); err == nil {
		return localPath
	}

	// Order matters: prefer the Go bin and /usr/local/bin (where the real
	// ProjectDiscovery tools live) BEFORE ~/.local/bin — a python package named
	// like a recon tool (e.g. the "httpx" HTTP library CLI) installs into
	// ~/.local/bin and would otherwise shadow the real tool and break probing.
	for _, dir := range []string{
		filepath.Join(os.Getenv("HOME"), "go", "bin"),
		"/usr/local/bin",
		"/opt/venv/bin",
		filepath.Join(os.Getenv("HOME"), ".local", "bin"), // pip/pipx installs (waymore/dirsearch/uro)
	} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil { // #nosec G703 -- name passed strict bare-ASCII validation before findTool is called
			return p
		}
	}

	if path, err := exec.LookPath(name); err == nil {
		return path
	}

	return name
}

func (e *Executor) extendedPath() string {
	existing := os.Getenv("PATH")
	extra := []string{
		e.cfg.ToolsDir,
		filepath.Join(os.Getenv("HOME"), "go", "bin"),
		"/opt/venv/bin",
		filepath.Join(os.Getenv("HOME"), ".local", "bin"), // pip/pipx installs (waymore)
		"/usr/local/go/bin",
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
	}
	return strings.Join(append(extra, existing), ":")
}

func (e *Executor) RunWithInputCallback(ctx context.Context, input io.Reader, taskID string, callback LineCallback, name string, args ...string) error {
	if err := validateToolName(name); err != nil {
		return err
	}
	if e.toolFree {
		return fmt.Errorf("external tool %s disabled", name)
	}
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}

	toolPath := e.findTool(name)
	cmd := exec.CommandContext(ctx, toolPath, args...) // #nosec G204,G702 -- toolPath derives from a validated bare executable name and fixed search directories
	cmd.Env = e.cmdEnv(name)
	cmd.Stdin = input
	hardenProc(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}

	e.registerActiveProc(taskID, cmd)
	defer e.unregisterActiveProc(taskID, cmd)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := scanStreamLines(stdout, maxToolStdoutLineBytes, func(line string) {
			if line != "" && callback != nil {
				e.safeCallback(name, callback, line)
			}
		}, func(dropped int) {
			if e.logger != nil {
				e.logger.Warn("Dropped oversized tool stdout line", "tool", name, "bytes", dropped)
			}
		}); err != nil && e.logger != nil {
			e.logger.Warn("Tool stdout stream read error", "tool", name, "error", err)
		}
	}()
	var errTail stderrTail
	go func() {
		defer wg.Done()
		if err := scanStreamLines(stderr, maxToolStderrLineBytes, func(line string) {
			if e.logger != nil {
				e.logger.Debug("Tool stderr", "tool", name, "line", line)
			}
			errTail.add(line)
		}, func(dropped int) {
			if e.logger != nil {
				e.logger.Warn("Dropped oversized tool stderr line", "tool", name, "bytes", dropped)
			}
		}); err != nil && e.logger != nil {
			e.logger.Warn("Tool stderr stream read error", "tool", name, "error", err)
		}
	}()
	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if tail := errTail.string(); tail != "" {
			return fmt.Errorf("%w: %s", err, tail)
		}
		return err
	}
	return nil
}

func (e *Executor) RunWithInput(ctx context.Context, input io.Reader, name string, args ...string) (*ExecResult, error) {
	if err := validateToolName(name); err != nil {
		return nil, err
	}
	if e.toolFree {
		return nil, fmt.Errorf("external tool %s disabled", name)
	}
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	start := time.Now()
	toolPath := e.findTool(name)
	cmd := exec.CommandContext(ctx, toolPath, args...) // #nosec G204,G702 -- toolPath derives from a validated bare executable name and fixed search directories
	cmd.Env = e.cmdEnv(name)
	cmd.Stdin = input
	hardenProc(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return result, fmt.Errorf("run %s: %w", name, err)
		}
	}

	return result, nil
}
