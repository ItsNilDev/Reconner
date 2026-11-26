package tools

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/pkg/logger"
)

func TestExecutorSparseConfigDoesNotDeadlock(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := exec.Run(ctx, "sh", "-c", "printf ready")
	if err != nil {
		t.Fatalf("sparse-config executor failed: %v", err)
	}
	if result.Stdout != "ready" {
		t.Fatalf("stdout = %q, want ready", result.Stdout)
	}
}

func TestExecutorRejectsUntrustedExecutableNames(t *testing.T) {
	exec := NewExecutor(&config.Config{ToolsDir: t.TempDir()}, logger.New("error"))
	for _, name := range []string{"", ".", "..", "../sh", "/bin/sh", `..\sh`, "sh;touch", "sh name", "🔥"} {
		t.Run(name, func(t *testing.T) {
			if exec.IsToolAvailable(name) {
				t.Fatalf("unsafe tool %q reported available", name)
			}
			if _, err := exec.Run(context.Background(), name); err == nil {
				t.Fatalf("Run accepted unsafe tool %q", name)
			}
			if err := exec.RunWithCallback(context.Background(), "task", nil, name); err == nil {
				t.Fatalf("RunWithCallback accepted unsafe tool %q", name)
			}
			if _, err := exec.RunWithInput(context.Background(), strings.NewReader("input"), name); err == nil {
				t.Fatalf("RunWithInput accepted unsafe tool %q", name)
			}
			if err := exec.RunWithInputCallback(context.Background(), strings.NewReader("input"), "task", nil, name); err == nil {
				t.Fatalf("RunWithInputCallback accepted unsafe tool %q", name)
			}
		})
	}
}

func TestToolFreeExecutorDisablesInputVariants(t *testing.T) {
	exec := NewToolFreeExecutor(&config.Config{ToolsDir: t.TempDir()}, logger.New("error"))
	if _, err := exec.RunWithInput(context.Background(), strings.NewReader("payload"), "sh"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("RunWithInput error = %v, want disabled", err)
	}
	if err := exec.RunWithInputCallback(context.Background(), strings.NewReader("payload"), "task", nil, "sh"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("RunWithInputCallback error = %v, want disabled", err)
	}
}

func TestRunWithCallbackSurfacesStderrOnFailure(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	// Mimic a tool that rejects a flag and exits non-zero (httpx exit status 2):
	// the returned error must carry the tool's own stderr message, not just the code.
	err := exec.RunWithCallback(context.Background(), "task", nil, "sh",
		"-c", "echo 'flag provided but not defined: -bogus' 1>&2; exit 2")
	if err == nil {
		t.Fatal("expected a non-zero-exit error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("error must include the stderr reason, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 2") {
		t.Fatalf("error must still include the exit code, got: %v", err)
	}
}

func TestRunWithCallbackNoErrorOnCleanExit(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	var lines []string
	err := exec.RunWithCallback(context.Background(), "task", func(l string) { lines = append(lines, l) },
		"sh", "-c", "echo one; echo two; echo noise 1>&2")
	if err != nil {
		t.Fatalf("clean exit must not error even with stderr output, got: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 stdout lines, got %v", lines)
	}
}

func TestStderrTailBounded(t *testing.T) {
	var tail stderrTail
	for i := 0; i < 20; i++ {
		tail.add(strings.Repeat("x", 100))
	}
	tail.add("") // blank lines ignored
	got := tail.string()
	if got == "" {
		t.Fatal("tail should retain recent lines")
	}
	if len(got) > 400+len("…") { // maxLen 400 + the 3-byte ellipsis rune
		t.Fatalf("tail must be length-bounded, got %d", len(got))
	}
}

func TestToolNameValidatorAllowsCuratedBareNames(t *testing.T) {
	for _, name := range []string{"httpx", "python3", "nuclei-templates", "tool_v2.1", "c++"} {
		if err := validateToolName(name); err != nil {
			t.Fatalf("validateToolName(%q): %v", name, err)
		}
	}
}

func TestRunWithCallbackHandlesLargeStdoutLineAndContinues(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var lines []string
	err := exec.RunWithCallback(ctx, "large-stdout", func(l string) {
		lines = append(lines, l)
	}, "sh", "-c", `head -c 2097152 /dev/zero | tr '\0' 'a'; printf '\nafter-large\n'`)
	if err != nil {
		t.Fatalf("RunWithCallback failed on 2MB stdout line: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (2MB line + trailing normal line)", len(lines))
	}
	if len(lines[0]) != 2*1024*1024 {
		t.Fatalf("first line length = %d, want %d", len(lines[0]), 2*1024*1024)
	}
	if lines[1] != "after-large" {
		t.Fatalf("second line = %q, want %q", lines[1], "after-large")
	}
}

func TestScanStreamLinesDrainsOversizedLineAndContinues(t *testing.T) {
	t.Parallel()

	t.Run("small_oversized_and_resumes", func(t *testing.T) {
		t.Parallel()
		input := "before\n" + strings.Repeat("X", 200) + "\nafter\r\nfinal-no-eol"
		var got []string
		var dropped []int
		err := scanStreamLines(strings.NewReader(input), 64, func(line string) {
			got = append(got, line)
		}, func(n int) {
			dropped = append(dropped, n)
		})
		if err != nil {
			t.Fatalf("scanStreamLines error: %v", err)
		}
		if len(dropped) != 1 || dropped[0] != 201 {
			t.Fatalf("dropped = %v, want [201]", dropped)
		}
		want := []string{"before", "after", "final-no-eol"}
		if len(got) != len(want) {
			t.Fatalf("got %q, want %q", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("line[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("multi_chunk_oversized_over_64k_resumes", func(t *testing.T) {
		t.Parallel()
		const oversizedLen = 200 * 1024
		input := "head\n" + strings.Repeat("A", oversizedLen) + "\ntail\n"
		var got []string
		var dropped []int
		err := scanStreamLines(strings.NewReader(input), 128*1024, func(line string) {
			got = append(got, line)
		}, func(n int) {
			dropped = append(dropped, n)
		})
		if err != nil {
			t.Fatalf("scanStreamLines error: %v", err)
		}
		if len(dropped) != 1 || dropped[0] != oversizedLen+1 {
			t.Fatalf("dropped = %v, want [%d]", dropped, oversizedLen+1)
		}
		if len(got) != 2 || got[0] != "head" || got[1] != "tail" {
			t.Fatalf("got %q, want [head tail]", got)
		}
	})

	t.Run("oversized_over_64k_eof_no_newline", func(t *testing.T) {
		t.Parallel()
		const oversizedLen = 200 * 1024
		input := "first\n" + strings.Repeat("B", oversizedLen)
		var got []string
		var dropped []int
		err := scanStreamLines(strings.NewReader(input), 128*1024, func(line string) {
			got = append(got, line)
		}, func(n int) {
			dropped = append(dropped, n)
		})
		if err != nil {
			t.Fatalf("scanStreamLines error: %v", err)
		}
		if len(dropped) != 1 || dropped[0] != oversizedLen {
			t.Fatalf("dropped = %v, want [%d]", dropped, oversizedLen)
		}
		if len(got) != 1 || got[0] != "first" {
			t.Fatalf("got %q, want [first]", got)
		}
	})

	t.Run("exact_boundary_64k_crlf", func(t *testing.T) {
		t.Parallel()
		payload := strings.Repeat("C", 64*1024)
		input := payload + "\r\nafter\n"
		var got []string
		var dropped []int
		err := scanStreamLines(strings.NewReader(input), 64*1024, func(line string) {
			got = append(got, line)
		}, func(n int) {
			dropped = append(dropped, n)
		})
		if err != nil {
			t.Fatalf("scanStreamLines error: %v", err)
		}
		if len(dropped) != 0 {
			t.Fatalf("dropped = %v, want none", dropped)
		}
		if len(got) != 2 || got[0] != payload || got[1] != "after" {
			t.Fatalf("got %d lines, want exact 64KiB payload and after", len(got))
		}
	})

	t.Run("exact_boundary_65535_crlf", func(t *testing.T) {
		t.Parallel()
		payload := strings.Repeat("D", 65535)
		input := payload + "\r\nafter\n"
		var got []string
		var dropped []int
		err := scanStreamLines(strings.NewReader(input), 65535, func(line string) {
			got = append(got, line)
		}, func(n int) {
			dropped = append(dropped, n)
		})
		if err != nil {
			t.Fatalf("scanStreamLines error: %v", err)
		}
		if len(dropped) != 0 {
			t.Fatalf("dropped = %v, want none", dropped)
		}
		if len(got) != 2 || got[0] != payload || got[1] != "after" {
			t.Fatalf("got %d lines, want exact 65535-byte payload and after", len(got))
		}
	})
}

func TestRunWithCallbackDrainsLargeStderrWithoutHanging(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var lines []string
	// Emit >64 KiB on a single stderr line plus a normal stdout line.
	err := exec.RunWithCallback(ctx, "large-stderr", func(l string) {
		lines = append(lines, l)
	}, "sh", "-c", `(head -c 131072 /dev/zero | tr '\0' 'e'; printf '\n') 1>&2; printf 'ok-stdout\n'`)
	if err != nil {
		t.Fatalf("RunWithCallback failed on >64KB stderr line: %v", err)
	}
	if len(lines) != 1 || lines[0] != "ok-stdout" {
		t.Fatalf("stdout lines = %q, want [ok-stdout]", lines)
	}
}

func TestKillTaskTerminatesAllConcurrentProcessesSharingKey(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{
		Limits: config.ResourceLimits{MaxToolExecutions: 4},
	}, logger.New("error"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const key = "shared-target"
	ready := make(chan struct{}, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := exec.RunWithCallback(ctx, key, func(line string) {
				if line == "started" {
					ready <- struct{}{}
				}
			}, "sh", "-c", "echo started; exec sleep 30")
			errs <- err
		}()
	}

	for range 2 {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent processes to start")
		}
	}

	exec.KillTask(key)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("KillTask did not terminate both concurrent processes sharing key")
	}

	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("expected killed process to return an error")
		}
	}
}
