package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/secret"
)

const telegramAPIBase = "https://api.telegram.org"

var telegramTokenRE = regexp.MustCompile(`^[0-9]{6,12}:[A-Za-z0-9_-]{20,}$`)
var telegramChatIDRE = regexp.MustCompile(`^-?[0-9]{1,20}$`)

type TelegramChat struct {
	ID                  string `json:"id"`
	ChatID              string `json:"chat_id"`
	Label               string `json:"label"`
	Role                string `json:"role"`
	Enabled             bool   `json:"enabled"`
	NotifyScanStarted   bool   `json:"notify_scan_started"`
	NotifyPhaseFinished bool   `json:"notify_phase_finished"`
	NotifyScanFinished  bool   `json:"notify_scan_finished"`
	NotifyFindings      bool   `json:"notify_findings"`
	NotifyMonitoring    bool   `json:"notify_monitoring"`
	// Watch-tier alerts. The breadth/watch tier is a separate workload with its
	// own volume: a watch round runs per project every 30 minutes, so its start
	// and finish messages are OFF by default. The scope-landed alert is ON — a
	// newly eligible host is the one event the operator must not miss.
	NotifyWatchScanStarted  bool   `json:"notify_watch_scan_started"`
	NotifyWatchScanFinished bool   `json:"notify_watch_scan_finished"`
	NotifyScopeLanded       bool   `json:"notify_scope_landed"`
	NotifyNewHost           bool   `json:"notify_new_host"`
	NotifyProgramScope      bool   `json:"notify_program_scope"`
	NotifyHTTPStatus        bool   `json:"notify_http_status"`
	CreatedAt               string `json:"created_at"`
	UpdatedAt               string `json:"updated_at"`
}

type TelegramState struct {
	Configured      bool           `json:"configured"`
	Enabled         bool           `json:"enabled"`
	MaskedToken     string         `json:"masked_token"`
	BotUsername     string         `json:"bot_username"`
	Connected       bool           `json:"connected"`
	LastError       string         `json:"last_error"`
	LastConnectedAt string         `json:"last_connected_at"`
	Pending         int            `json:"pending"`
	Failed          int            `json:"failed"`
	Chats           []TelegramChat `json:"chats"`
}

type tgInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data,omitempty"`
}

type tgInlineKeyboard struct {
	Rows [][]tgInlineButton `json:"inline_keyboard"`
}

type tgAPIResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

type tgUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type tgChat struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
}

type tgMessage struct {
	MessageID int64  `json:"message_id"`
	From      tgUser `json:"from"`
	Chat      tgChat `json:"chat"`
	Text      string `json:"text"`
}

type tgCallbackQuery struct {
	ID      string     `json:"id"`
	From    tgUser     `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgUpdate struct {
	UpdateID      int64            `json:"update_id"`
	Message       *tgMessage       `json:"message"`
	CallbackQuery *tgCallbackQuery `json:"callback_query"`
}

type tgStatusItem struct {
	Target  string `json:"target,omitempty"`
	URL     string `json:"url"`
	OldCode int    `json:"old_code"`
	NewCode int    `json:"new_code"`
	OldText string `json:"old_text,omitempty"`
	NewText string `json:"new_text,omitempty"`
}

type tgScopeItem struct {
	Target      string `json:"target,omitempty"`
	ProgramID   string `json:"program_id"`
	ProgramName string `json:"program_name"`
	EventType   string `json:"event_type"`
	Identifier  string `json:"identifier"`
}

type tgMonitorItem struct {
	Target     string `json:"target,omitempty"`
	ChangeType string `json:"change_type"`
	URL        string `json:"url"`
	Summary    string `json:"summary"`
}

type tgFindingItem struct {
	Target    string `json:"target,omitempty"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	URL       string `json:"url"`
	Parameter string `json:"parameter,omitempty"`
	Proof     string `json:"proof,omitempty"`
}

type tgOutboxRow struct {
	id          string
	chatEntryID string
	chatID      string
	category    string
	message     string
	keyboard    string
	attempts    int
	batchKey    string
	targetID    string
	itemJSON    string
}

const (
	tgBatchMaxItems = 20
	tgBatchMaxRunes = 3500
	tgBatchMaxMsgs  = 2
)

// TelegramBot is both a durable notification sink for the scheduler and a
// long-polling management bot. Long polling keeps self-hosted installations
// usable behind NAT; no public webhook URL is required.
type TelegramBot struct {
	h              *Handler
	client         *http.Client
	apiBase        string
	wake           chan struct{}
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	start          sync.Once
	stop           sync.Once
	offset         atomic.Int64
	config         atomic.Uint64 // changes invalidate in-flight long polls from an old token
	scans          sync.Map      // task id -> scan start time; keeps phase finding sweeps lossless
	coalesceWindow time.Duration
}

func NewTelegramBot(h *Handler) *TelegramBot {
	return &TelegramBot{
		h: h, apiBase: telegramAPIBase, wake: make(chan struct{}, 1),
		client:         &http.Client{Timeout: 40 * time.Second},
		coalesceWindow: 10 * time.Second,
	}
}

func (b *TelegramBot) Start() {
	b.start.Do(func() {
		var lastUpdateID int64
		_ = b.h.db.QueryRow(`SELECT COALESCE(last_update_id,0) FROM telegram_config WHERE id=1`).Scan(&lastUpdateID)
		if lastUpdateID > 0 {
			b.offset.Store(lastUpdateID + 1)
		}
		ctx, cancel := context.WithCancel(context.Background())
		b.cancel = cancel
		b.wg.Add(2)
		go b.pollLoop(ctx)
		go b.outboxLoop(ctx)
	})
}

func (b *TelegramBot) Stop() {
	b.stop.Do(func() {
		if b.cancel != nil {
			b.cancel()
		}
		b.wg.Wait()
	})
}

func (b *TelegramBot) Wake() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *TelegramBot) botToken(ctx context.Context) (string, bool, error) {
	var encrypted string
	var enabled int
	err := b.h.db.QueryRowContext(ctx, `SELECT encrypted_bot_token,enabled FROM telegram_config WHERE id=1`).Scan(&encrypted, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return secret.New(b.h.cfg.SessionSecret).Decrypt(encrypted), enabled == 1, nil
}

func (b *TelegramBot) State(ctx context.Context) (TelegramState, error) {
	state := TelegramState{Chats: []TelegramChat{}}
	var encrypted string
	var enabled int
	var lastConnected sql.NullString
	err := b.h.db.QueryRowContext(ctx, `SELECT encrypted_bot_token,enabled,bot_username,last_error,last_connected_at
		FROM telegram_config WHERE id=1`).Scan(&encrypted, &enabled, &state.BotUsername, &state.LastError, &lastConnected)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return state, err
	}
	if err == nil {
		token := secret.New(b.h.cfg.SessionSecret).Decrypt(encrypted)
		state.Configured = token != ""
		state.Enabled = enabled == 1
		state.MaskedToken = maskKey(token)
		if lastConnected.Valid {
			state.LastConnectedAt = lastConnected.String
			if t, parseErr := time.Parse("2006-01-02 15:04:05", lastConnected.String); parseErr == nil {
				state.Connected = state.Enabled && state.LastError == "" && time.Since(t) < 2*time.Minute
			}
		}
	}

	rows, err := b.h.db.QueryContext(ctx, `SELECT id,chat_id,label,role,enabled,
		notify_scan_started,notify_phase_finished,notify_scan_finished,notify_findings,notify_monitoring,
		notify_watch_scan_started,notify_watch_scan_finished,notify_scope_landed,notify_new_host,
		notify_program_scope,notify_http_status,
		created_at,updated_at FROM telegram_chats ORDER BY created_at`)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var c TelegramChat
		var enabled, a, p, f, findings, monitoring, ws, wf, sl, nh, ps, hs int
		if err := rows.Scan(&c.ID, &c.ChatID, &c.Label, &c.Role, &enabled, &a, &p, &f, &findings, &monitoring,
			&ws, &wf, &sl, &nh, &ps, &hs, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return state, err
		}
		c.Enabled, c.NotifyScanStarted, c.NotifyPhaseFinished = enabled == 1, a == 1, p == 1
		c.NotifyScanFinished, c.NotifyFindings, c.NotifyMonitoring = f == 1, findings == 1, monitoring == 1
		c.NotifyWatchScanStarted, c.NotifyWatchScanFinished, c.NotifyScopeLanded = ws == 1, wf == 1, sl == 1
		c.NotifyNewHost, c.NotifyProgramScope, c.NotifyHTTPStatus = nh == 1, ps == 1, hs == 1
		state.Chats = append(state.Chats, c)
	}
	if err := rows.Err(); err != nil {
		return state, err
	}
	_ = b.h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_outbox WHERE status='pending'`).Scan(&state.Pending)
	_ = b.h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_outbox WHERE status='failed'`).Scan(&state.Failed)
	return state, nil
}

// Configure validates a replacement token with getMe before sealing it. A nil
// token preserves the current one; an explicit empty token disconnects the bot.
func (b *TelegramBot) Configure(ctx context.Context, token *string, enabled *bool) error {
	// Invalidate any long poll before validation or persistence starts. This
	// closes the narrow window where an old bot response could otherwise claim
	// an update cursor immediately after a replacement token is stored.
	b.config.Add(1)
	current, currentEnabled, err := b.botToken(ctx)
	if err != nil {
		return err
	}
	next, nextEnabled := current, currentEnabled
	username := ""
	if token != nil {
		next = strings.TrimSpace(*token)
		if next != "" {
			if !telegramTokenRE.MatchString(next) {
				return fmt.Errorf("invalid BotFather token format")
			}
			user, verifyErr := b.getMe(ctx, next)
			if verifyErr != nil {
				return fmt.Errorf("Telegram rejected the bot token: %w", verifyErr)
			}
			username = user.Username
		} else {
			nextEnabled = false
		}
	}
	if enabled != nil {
		nextEnabled = *enabled
	}
	if nextEnabled && next == "" {
		return fmt.Errorf("set a BotFather token before enabling Telegram")
	}
	if username == "" && next != "" {
		var saved string
		_ = b.h.db.QueryRowContext(ctx, `SELECT bot_username FROM telegram_config WHERE id=1`).Scan(&saved)
		username = saved
	}
	tokenChanged := token != nil && next != current
	sealed := secret.New(b.h.cfg.SessionSecret).Encrypt(next)
	_, err = b.h.db.ExecContext(ctx, `INSERT INTO telegram_config(id,encrypted_bot_token,enabled,bot_username,last_error,updated_at)
		VALUES(1,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET encrypted_bot_token=excluded.encrypted_bot_token,
		enabled=excluded.enabled,bot_username=excluded.bot_username,last_error='',
		last_update_id=CASE WHEN ?=1 THEN 0 ELSE telegram_config.last_update_id END,
		updated_at=CURRENT_TIMESTAMP`,
		sealed, boolInt(nextEnabled), username, "", boolInt(tokenChanged))
	if err == nil {
		var lastUpdateID int64
		_ = b.h.db.QueryRowContext(ctx, `SELECT COALESCE(last_update_id,0) FROM telegram_config WHERE id=1`).Scan(&lastUpdateID)
		if lastUpdateID > 0 {
			b.offset.Store(lastUpdateID + 1)
		} else {
			b.offset.Store(0)
		}
		if nextEnabled && next != "" {
			// Command registration is best-effort; polling and direct commands do
			// not depend on Telegram rendering the menu immediately.
			_, _ = b.call(ctx, next, "setMyCommands", map[string]any{"commands": []map[string]string{
				{"command": "status", "description": "Platform and scan status"},
				{"command": "targets", "description": "List targets"},
				{"command": "scans", "description": "Recent scans"},
				{"command": "findings", "description": "Latest verified findings"},
				{"command": "scan", "description": "Start a target scan"},
				{"command": "pause", "description": "Pause a target scan"},
				{"command": "resume", "description": "Resume a target scan"},
				{"command": "skip", "description": "Skip the current scan phase"},
				{"command": "cancel", "description": "Cancel a target scan"},
				{"command": "help", "description": "Show commands for this chat role"},
			}}, nil)
		}
		b.Wake()
	}
	return err
}

func (b *TelegramBot) AddChat(ctx context.Context, c TelegramChat) (TelegramChat, error) {
	c.ChatID = strings.TrimSpace(c.ChatID)
	c.Label = strings.TrimSpace(c.Label)
	c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	if !telegramChatIDRE.MatchString(c.ChatID) {
		return c, fmt.Errorf("chat id must be a signed numeric Telegram chat id")
	}
	if len(c.Label) > 80 {
		return c, fmt.Errorf("chat label is too long")
	}
	if roleRank(c.Role) < 0 {
		return c, fmt.Errorf("role must be viewer, operator or admin")
	}
	c.ID = uuid.NewString()
	// New chats receive all high-signal event types by default. The watch tier
	// stays quiet: a watch round runs per project every 30 minutes, so its
	// start/finish messages would flood the channel. The scope-landed alert is
	// ON — a newly eligible host is the one event the operator must not miss.
	// Routine scan start/phase/finish messages belong in Scan activity. A new
	// chat starts quiet for those, while the four daily signals stay ON. The
	// finding sweep still runs from the lifecycle callbacks (B6).
	c.Enabled, c.NotifyScanStarted, c.NotifyPhaseFinished = true, false, false
	c.NotifyScanFinished, c.NotifyFindings, c.NotifyMonitoring = false, true, true
	c.NotifyWatchScanStarted, c.NotifyWatchScanFinished = false, false
	c.NotifyScopeLanded, c.NotifyNewHost = true, true
	// The four daily signals stay ON for a new chat. Routine scan lifecycle
	// messages for the watch tier stay OFF (B9).
	c.NotifyProgramScope, c.NotifyHTTPStatus = true, true
	_, err := b.h.db.ExecContext(ctx, `INSERT INTO telegram_chats(id,chat_id,label,role,enabled,
		notify_scan_started,notify_phase_finished,notify_scan_finished,notify_findings,notify_monitoring,
		notify_watch_scan_started,notify_watch_scan_finished,notify_scope_landed,notify_new_host,
		notify_program_scope,notify_http_status)
		VALUES(?,?,?,?,?,?,?,?,1,1,?,?,?,?,?,?)`, c.ID, c.ChatID, c.Label, c.Role,
		boolInt(c.Enabled), boolInt(c.NotifyScanStarted), boolInt(c.NotifyPhaseFinished), boolInt(c.NotifyScanFinished),
		boolInt(c.NotifyWatchScanStarted), boolInt(c.NotifyWatchScanFinished), boolInt(c.NotifyScopeLanded), boolInt(c.NotifyNewHost),
		boolInt(c.NotifyProgramScope), boolInt(c.NotifyHTTPStatus))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return c, fmt.Errorf("that chat id is already configured")
		}
		return c, err
	}
	b.Wake()
	state, err := b.State(ctx)
	if err == nil {
		for _, saved := range state.Chats {
			if saved.ID == c.ID {
				return saved, nil
			}
		}
	}
	return c, err
}

func (b *TelegramBot) UpdateChat(ctx context.Context, id string, c TelegramChat) error {
	c.Label = strings.TrimSpace(c.Label)
	c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	if len(c.Label) > 80 {
		return fmt.Errorf("chat label is too long")
	}
	if roleRank(c.Role) < 0 {
		return fmt.Errorf("role must be viewer, operator or admin")
	}
	res, err := b.h.db.ExecContext(ctx, `UPDATE telegram_chats SET label=?,role=?,enabled=?,
		notify_scan_started=?,notify_phase_finished=?,notify_scan_finished=?,notify_findings=?,notify_monitoring=?,
		notify_watch_scan_started=?,notify_watch_scan_finished=?,notify_scope_landed=?,notify_new_host=?,
		notify_program_scope=?,notify_http_status=?,
		updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		c.Label, c.Role, boolInt(c.Enabled), boolInt(c.NotifyScanStarted), boolInt(c.NotifyPhaseFinished),
		boolInt(c.NotifyScanFinished), boolInt(c.NotifyFindings), boolInt(c.NotifyMonitoring),
		boolInt(c.NotifyWatchScanStarted), boolInt(c.NotifyWatchScanFinished), boolInt(c.NotifyScopeLanded), boolInt(c.NotifyNewHost),
		boolInt(c.NotifyProgramScope), boolInt(c.NotifyHTTPStatus), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	b.Wake()
	return nil
}

func (b *TelegramBot) DeleteChat(ctx context.Context, id string) error {
	res, err := b.h.db.ExecContext(ctx, `DELETE FROM telegram_chats WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (b *TelegramBot) TestChat(ctx context.Context, entryID string) error {
	token, enabled, err := b.botToken(ctx)
	if err != nil {
		return err
	}
	if token == "" || !enabled {
		return fmt.Errorf("Telegram bot is not enabled")
	}
	var chatID string
	if err := b.h.db.QueryRowContext(ctx, `SELECT chat_id FROM telegram_chats WHERE id=? AND enabled=1`, entryID).Scan(&chatID); err != nil {
		return fmt.Errorf("enabled chat not found")
	}
	return b.sendMessage(ctx, token, chatID, "Reconner is connected. Scan, phase and verified-finding notifications are enabled for this chat.", nil)
}

func (b *TelegramBot) RetryFailed(ctx context.Context) error {
	_, err := b.h.db.ExecContext(ctx, `UPDATE telegram_outbox SET status='pending',attempts=0,last_error='',next_attempt_at=CURRENT_TIMESTAMP WHERE status='failed'`)
	b.Wake()
	return err
}

func (b *TelegramBot) getMe(ctx context.Context, token string) (tgUser, error) {
	var user tgUser
	resp, err := b.call(ctx, token, "getMe", map[string]any{}, &user)
	if err != nil {
		return user, err
	}
	if !resp.OK {
		return user, fmt.Errorf("%s", resp.Description)
	}
	return user, nil
}

func (b *TelegramBot) call(ctx context.Context, token, method string, payload any, result any) (tgAPIResponse, error) {
	var envelope tgAPIResponse
	body, err := json.Marshal(payload)
	if err != nil {
		return envelope, err
	}
	endpoint := strings.TrimRight(b.apiBase, "/") + "/bot" + token + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return envelope, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Reconner-Telegram/1")
	res, err := b.client.Do(req)
	if err != nil {
		return envelope, fmt.Errorf("%s", redactTelegramError(err.Error(), token))
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return envelope, err
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return envelope, fmt.Errorf("Telegram returned HTTP %d with an invalid response", res.StatusCode)
	}
	if result != nil && len(envelope.Result) > 0 && string(envelope.Result) != "null" {
		if err := json.Unmarshal(envelope.Result, result); err != nil {
			return envelope, err
		}
	}
	if !envelope.OK {
		return envelope, fmt.Errorf("Telegram API: %s", envelope.Description)
	}
	return envelope, nil
}

func redactTelegramError(message, token string) string {
	if token != "" {
		message = strings.ReplaceAll(message, token, "<redacted-bot-token>")
	}
	return message
}

func (b *TelegramBot) sendMessage(ctx context.Context, token, chatID, text string, keyboard *tgInlineKeyboard) error {
	if len([]rune(text)) > 4000 {
		text = string([]rune(text)[:3990]) + "\n…"
	}
	payload := map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true}
	if keyboard != nil && len(keyboard.Rows) > 0 {
		payload["reply_markup"] = keyboard
	}
	_, err := b.call(ctx, token, "sendMessage", payload, nil)
	return err
}

func (b *TelegramBot) answerCallback(ctx context.Context, token, id, text string) {
	_, _ = b.call(ctx, token, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}

func (b *TelegramBot) setConnection(errorText string, connected bool) {
	errorText = redactTelegramError(errorText, "")
	if len(errorText) > 1000 {
		errorText = errorText[:1000]
	}
	if connected {
		_, _ = b.h.db.Exec(`UPDATE telegram_config SET last_error='',last_connected_at=CURRENT_TIMESTAMP WHERE id=1`)
	} else {
		_, _ = b.h.db.Exec(`UPDATE telegram_config SET last_error=? WHERE id=1`, errorText)
	}
}

func (b *TelegramBot) pollLoop(ctx context.Context) {
	defer b.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		token, enabled, err := b.botToken(ctx)
		if err != nil || !enabled || token == "" {
			b.wait(ctx, 15*time.Second)
			continue
		}
		var updates []tgUpdate
		generation := b.config.Load()
		payload := map[string]any{
			"offset": b.offset.Load(), "timeout": 25,
			"allowed_updates": []string{"message", "callback_query"},
		}
		_, err = b.call(ctx, token, "getUpdates", payload, &updates)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			b.setConnection(redactTelegramError(err.Error(), token), false)
			b.wait(ctx, 5*time.Second)
			continue
		}
		// A settings change can finish while getUpdates is blocked. Never execute
		// a late response obtained with a disabled or replaced bot token.
		activeToken, activeEnabled, activeErr := b.botToken(ctx)
		if activeErr != nil || !activeEnabled || activeToken != token || generation != b.config.Load() {
			continue
		}
		b.setConnection("", true)
		for _, update := range updates {
			if generation != b.config.Load() {
				break
			}
			if update.UpdateID < b.offset.Load() {
				continue
			}
			// Claim the update before executing it. Scan/target commands are safer
			// at-most-once than duplicated after a crash (especially /scan).
			claim, err := b.h.db.ExecContext(ctx, `UPDATE telegram_config SET last_update_id=?,updated_at=CURRENT_TIMESTAMP
				WHERE id=1 AND last_update_id<?`, update.UpdateID, update.UpdateID)
			if err != nil {
				b.setConnection(err.Error(), false)
				break
			}
			b.offset.Store(update.UpdateID + 1)
			if claimed, _ := claim.RowsAffected(); claimed == 0 {
				continue
			}
			b.handleUpdate(ctx, token, update)
		}
	}
}

func (b *TelegramBot) wait(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-b.wake:
	case <-t.C:
	}
}

func (b *TelegramBot) outboxLoop(ctx context.Context) {
	defer b.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.wake:
			b.drainOutbox(ctx)
		case <-ticker.C:
			b.drainOutbox(ctx)
		}
	}
}

func (b *TelegramBot) drainOutbox(ctx context.Context) {
	token, enabled, err := b.botToken(ctx)
	if err != nil || !enabled || token == "" {
		return
	}
	// Drop pending rows whose category was muted after they were queued.
	// Leaving them pending would flood the chat on re-enable, and the unique
	// key would block a newer event of the same kind (review finding #8).
	if _, err := b.h.db.ExecContext(ctx, `UPDATE telegram_outbox SET status='sent',sent_at=CURRENT_TIMESTAMP,
		last_error='muted before delivery'
		WHERE status='pending' AND id IN (
			SELECT o.id FROM telegram_outbox o JOIN telegram_chats c ON c.id=o.chat_entry_id
			WHERE CASE o.category
			  WHEN 'scan_started' THEN c.notify_scan_started
			  WHEN 'phase_finished' THEN c.notify_phase_finished
			  WHEN 'scan_finished' THEN c.notify_scan_finished
			  WHEN 'finding' THEN c.notify_findings
			  WHEN 'monitoring' THEN c.notify_monitoring
			  WHEN 'http_status' THEN c.notify_http_status
			  WHEN 'program_scope' THEN c.notify_program_scope
			  WHEN 'watch_scan_started' THEN c.notify_watch_scan_started
			  WHEN 'watch_scan_finished' THEN c.notify_watch_scan_finished
			  WHEN 'scope_landed' THEN c.notify_scope_landed
			  WHEN 'new_host' THEN c.notify_new_host
			  ELSE 1 END <> 1
		)`); err != nil {
		b.logDBError("telegram mute sweep", err)
	}
	// Re-check the category switch at delivery time. A row queued before an
	// operator muted the category must not be sent two seconds later (B11).
	// Findings also get priority so a routine backlog cannot block them.
	rows, err := b.h.db.QueryContext(ctx, `SELECT o.id,o.chat_entry_id,c.chat_id,o.category,o.message,o.keyboard_json,o.attempts,
		COALESCE(o.batch_key,''),COALESCE(o.target_id,''),COALESCE(o.item_json,'')
		FROM telegram_outbox o JOIN telegram_chats c ON c.id=o.chat_entry_id
		WHERE o.status='pending' AND o.next_attempt_at<=CURRENT_TIMESTAMP AND c.enabled=1
		  AND CASE o.category
		    WHEN 'scan_started' THEN c.notify_scan_started
		    WHEN 'phase_finished' THEN c.notify_phase_finished
		    WHEN 'scan_finished' THEN c.notify_scan_finished
		    WHEN 'finding' THEN c.notify_findings
		    WHEN 'monitoring' THEN c.notify_monitoring
		    WHEN 'http_status' THEN c.notify_http_status
		    WHEN 'program_scope' THEN c.notify_program_scope
		    WHEN 'watch_scan_started' THEN c.notify_watch_scan_started
		    WHEN 'watch_scan_finished' THEN c.notify_watch_scan_finished
		    WHEN 'scope_landed' THEN c.notify_scope_landed
		    WHEN 'new_host' THEN c.notify_new_host
		    ELSE 1 END = 1
		ORDER BY CASE WHEN o.category='finding' THEN 0 ELSE 1 END, o.created_at, o.rowid LIMIT 50`)
	if err != nil {
		b.logDBError("telegram outbox query", err)
		return
	}
	var items []tgOutboxRow
	for rows.Next() {
		var v tgOutboxRow
		if err := rows.Scan(&v.id, &v.chatEntryID, &v.chatID, &v.category, &v.message, &v.keyboard, &v.attempts, &v.batchKey, &v.targetID, &v.itemJSON); err != nil {
			b.logDBError("telegram outbox scan", err)
			continue
		}
		items = append(items, v)
	}
	if err := rows.Err(); err != nil {
		b.logDBError("telegram outbox rows", err)
	}
	rows.Close()

	seenBatches := make(map[string]bool)
	for _, v := range items {
		if v.batchKey == "" {
			keyboard := decodeInlineKeyboard(v.keyboard)
			sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			sendErr := b.sendMessage(sendCtx, token, v.chatID, v.message, keyboard)
			cancel()
			if sendErr == nil {
				b.markOutboxSent(ctx, []string{v.id})
				continue
			}
			b.markOutboxFailed(ctx, []string{v.id}, v.attempts, sendErr, token)
			continue
		}

		groupKey := v.chatEntryID + "\x00" + v.batchKey
		if seenBatches[groupKey] {
			continue
		}
		seenBatches[groupKey] = true

		batchRows, err := b.loadPendingBatch(ctx, v.chatEntryID, v.batchKey)
		if err != nil {
			b.logDBError("telegram load pending batch", err)
			continue
		}
		if len(batchRows) == 0 {
			continue
		}

		category := v.category
		targetID := v.targetID
		keyboardRaw := v.keyboard
		ids := make([]string, 0, len(batchRows))
		minAttempts := batchRows[0].attempts
		for _, r := range batchRows {
			ids = append(ids, r.id)
			if r.attempts < minAttempts {
				minAttempts = r.attempts
			}
			if targetID == "" && r.targetID != "" {
				targetID = r.targetID
			}
			if keyboardRaw == "" && r.keyboard != "" {
				keyboardRaw = r.keyboard
			}
		}
		keyboard := decodeInlineKeyboard(keyboardRaw)
		chunks := b.renderBatchMessages(ctx, category, targetID, batchRows)
		if len(chunks) == 0 {
			chunks = []tgPackedMessage{{text: batchRows[0].message, rowIDs: ids}}
		}

		var deliveredIDs []string
		var failedIDs []string
		var sendErr error
		for i, chunk := range chunks {
			var kb *tgInlineKeyboard
			if i == len(chunks)-1 {
				kb = keyboard
			}
			sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := b.sendMessage(sendCtx, token, v.chatID, chunk.text, kb)
			cancel()
			if err != nil {
				sendErr = err
				for j := i; j < len(chunks); j++ {
					failedIDs = append(failedIDs, chunks[j].rowIDs...)
				}
				break
			}
			deliveredIDs = append(deliveredIDs, chunk.rowIDs...)
		}
		if len(deliveredIDs) > 0 {
			b.markOutboxSent(ctx, deliveredIDs)
		}
		if sendErr != nil {
			if len(failedIDs) == 0 {
				failedIDs = ids
			}
			b.markOutboxFailed(ctx, failedIDs, minAttempts, sendErr, token)
		}
	}
}

func (b *TelegramBot) loadPendingBatch(ctx context.Context, chatEntryID, batchKey string) ([]tgOutboxRow, error) {
	rows, err := b.h.db.QueryContext(ctx, `SELECT id,category,message,keyboard_json,attempts,COALESCE(target_id,''),COALESCE(item_json,'')
		FROM telegram_outbox
		WHERE status='pending' AND chat_entry_id=? AND batch_key=?
		  AND (attempts = 0 OR next_attempt_at <= CURRENT_TIMESTAMP)
		ORDER BY created_at, rowid LIMIT 200`, chatEntryID, batchKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tgOutboxRow
	for rows.Next() {
		var r tgOutboxRow
		r.chatEntryID = chatEntryID
		r.batchKey = batchKey
		if err := rows.Scan(&r.id, &r.category, &r.message, &r.keyboard, &r.attempts, &r.targetID, &r.itemJSON); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (b *TelegramBot) markOutboxSent(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	if _, err := b.h.db.ExecContext(ctx, `UPDATE telegram_outbox SET status='sent',sent_at=CURRENT_TIMESTAMP,last_error='' WHERE id IN (`+placeholders+`)`, args...); err != nil {
		b.logDBError("telegram mark outbox sent", err)
	}
}

func (b *TelegramBot) markOutboxFailed(ctx context.Context, ids []string, minPrevAttempts int, sendErr error, token string) {
	if len(ids) == 0 {
		return
	}
	backoff := 1 << minInt(minPrevAttempts+1, 8)
	message := redactTelegramError(sendErr.Error(), token)
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, 2+len(ids))
	args = append(args, message, "+"+strconv.Itoa(backoff)+" seconds")
	for _, id := range ids {
		args = append(args, id)
	}
	if _, err := b.h.db.ExecContext(ctx, `UPDATE telegram_outbox
		SET status = CASE WHEN attempts + 1 >= 8 THEN 'failed' ELSE 'pending' END,
		    attempts = attempts + 1,
		    last_error = ?,
		    next_attempt_at = datetime('now', ?)
		WHERE id IN (`+placeholders+`)`, args...); err != nil {
		b.logDBError("telegram mark outbox failed", err)
	}
}

func decodeInlineKeyboard(raw string) *tgInlineKeyboard {
	if raw == "" {
		return nil
	}
	var k tgInlineKeyboard
	if json.Unmarshal([]byte(raw), &k) == nil {
		return &k
	}
	return nil
}

func telegramCategoryPreference(category string) string {
	return map[string]string{
		"scan_started": "notify_scan_started", "phase_finished": "notify_phase_finished",
		"scan_finished": "notify_scan_finished", "finding": "notify_findings", "monitoring": "notify_monitoring",
		// Watch-tier categories. They map to their own per-chat switches, so the
		// deep alerts and the breadth alerts never mix in one channel.
		"watch_scan_started": "notify_watch_scan_started", "watch_scan_finished": "notify_watch_scan_finished",
		"scope_landed": "notify_scope_landed", "new_host": "notify_new_host",
		"http_status": "notify_http_status", "program_scope": "notify_program_scope",
	}[category]
}

func (b *TelegramBot) findingCoalesceDelay() time.Duration {
	if b.coalesceWindow <= 0 {
		return 0
	}
	if b.coalesceWindow > 5*time.Second {
		return 5 * time.Second
	}
	return b.coalesceWindow
}

func (b *TelegramBot) enqueue(category, eventKey, text string, keyboard *tgInlineKeyboard) {
	b.enqueueBatched(category, eventKey, "", "", text, nil, keyboard, 0)
}

func (b *TelegramBot) enqueueBatched(category, eventKey, batchKey, targetID, fallbackMsg string, item any, keyboard *tgInlineKeyboard, delay time.Duration) {
	preference := telegramCategoryPreference(category)
	if preference == "" {
		return
	}
	keyboardJSON := ""
	if keyboard != nil {
		if raw, err := json.Marshal(keyboard); err == nil {
			keyboardJSON = string(raw)
		}
	}
	itemJSON := ""
	if item != nil {
		if raw, err := json.Marshal(item); err == nil {
			itemJSON = string(raw)
		}
	}
	var err error
	if delay > 0 {
		secs := int(delay / time.Second)
		if secs < 1 {
			secs = 1
		}
		query := `INSERT OR IGNORE INTO telegram_outbox(id,chat_entry_id,event_key,category,message,keyboard_json,batch_key,target_id,item_json,next_attempt_at)
			SELECT lower(hex(randomblob(16))),id,?,?,?,?,?,?,?,datetime('now', ?) FROM telegram_chats
			WHERE enabled=1 AND ` + preference + `=1
			  AND EXISTS (SELECT 1 FROM telegram_config WHERE id=1 AND enabled=1 AND encrypted_bot_token<>'')`
		_, err = b.h.db.Exec(query, eventKey, category, fallbackMsg, keyboardJSON, batchKey, targetID, itemJSON, "+"+strconv.Itoa(secs)+" seconds")
	} else {
		query := `INSERT OR IGNORE INTO telegram_outbox(id,chat_entry_id,event_key,category,message,keyboard_json,batch_key,target_id,item_json,next_attempt_at)
			SELECT lower(hex(randomblob(16))),id,?,?,?,?,?,?,?,CURRENT_TIMESTAMP FROM telegram_chats
			WHERE enabled=1 AND ` + preference + `=1
			  AND EXISTS (SELECT 1 FROM telegram_config WHERE id=1 AND enabled=1 AND encrypted_bot_token<>'')`
		_, err = b.h.db.Exec(query, eventKey, category, fallbackMsg, keyboardJSON, batchKey, targetID, itemJSON)
	}
	if err != nil {
		b.logDBError("telegram enqueue outbox", err)
		return
	}
	b.Wake()
}

type tgPackedMessage struct {
	text   string
	rowIDs []string
}

func (b *TelegramBot) renderBatchMessages(ctx context.Context, category, targetID string, rows []tgOutboxRow) []tgPackedMessage {
	if len(rows) == 0 {
		return nil
	}
	allIDs := make([]string, 0, len(rows))
	for _, r := range rows {
		allIDs = append(allIDs, r.id)
	}
	switch category {
	case "http_status":
		var items []tgStatusItem
		var itemRowIDs [][]string
		var unparsedIDs []string
		seen := make(map[string]int)
		fallbackTarget := ""
		for _, r := range rows {
			var it tgStatusItem
			if r.itemJSON == "" || json.Unmarshal([]byte(r.itemJSON), &it) != nil {
				unparsedIDs = append(unparsedIDs, r.id)
				continue
			}
			if fallbackTarget == "" && it.Target != "" {
				fallbackTarget = it.Target
			}
			dedupKey := fmt.Sprintf("%s\x00%d\x00%d\x00%s\x00%s", it.URL, it.OldCode, it.NewCode, it.OldText, it.NewText)
			if idx, ok := seen[dedupKey]; ok {
				itemRowIDs[idx] = append(itemRowIDs[idx], r.id)
				continue
			}
			seen[dedupKey] = len(items)
			items = append(items, it)
			itemRowIDs = append(itemRowIDs, []string{r.id})
		}
		if len(items) == 0 {
			return []tgPackedMessage{{text: rows[0].message, rowIDs: allIDs}}
		}
		label := b.targetLabel(ctx, targetID, "")
		if label == "" {
			label = fallbackTarget
		}
		chunks := formatHTTPStatusBatch(label, items, itemRowIDs)
		if len(unparsedIDs) > 0 && len(chunks) > 0 {
			chunks[0].rowIDs = append(chunks[0].rowIDs, unparsedIDs...)
		}
		return chunks

	case "program_scope":
		var items []tgScopeItem
		var itemRowIDs [][]string
		var unparsedIDs []string
		seen := make(map[string]int)
		fallbackTarget := ""
		progID, progName := "", ""
		for _, r := range rows {
			var it tgScopeItem
			if r.itemJSON == "" || json.Unmarshal([]byte(r.itemJSON), &it) != nil {
				unparsedIDs = append(unparsedIDs, r.id)
				continue
			}
			if fallbackTarget == "" && it.Target != "" {
				fallbackTarget = it.Target
			}
			if progID == "" && it.ProgramID != "" {
				progID = it.ProgramID
			}
			if progName == "" && it.ProgramName != "" {
				progName = it.ProgramName
			}
			dedupKey := it.EventType + "\x00" + it.Identifier
			if idx, ok := seen[dedupKey]; ok {
				itemRowIDs[idx] = append(itemRowIDs[idx], r.id)
				continue
			}
			seen[dedupKey] = len(items)
			items = append(items, it)
			itemRowIDs = append(itemRowIDs, []string{r.id})
		}
		if len(items) == 0 {
			return []tgPackedMessage{{text: rows[0].message, rowIDs: allIDs}}
		}
		label := b.targetLabel(ctx, targetID, "")
		if label == "" {
			label = fallbackTarget
		}
		if progID != "" {
			if resolved := b.programLabel(ctx, progID); resolved != "" && (progName == "" || resolved != shortBotID(progID)) {
				progName = resolved
			}
		}
		chunks := formatScopeBatch(label, progName, items, itemRowIDs)
		if len(unparsedIDs) > 0 && len(chunks) > 0 {
			chunks[0].rowIDs = append(chunks[0].rowIDs, unparsedIDs...)
		}
		return chunks

	case "monitoring":
		var items []tgMonitorItem
		var itemRowIDs [][]string
		var unparsedIDs []string
		seen := make(map[string]int)
		fallbackTarget := ""
		for _, r := range rows {
			var it tgMonitorItem
			if r.itemJSON == "" || json.Unmarshal([]byte(r.itemJSON), &it) != nil {
				unparsedIDs = append(unparsedIDs, r.id)
				continue
			}
			if fallbackTarget == "" && it.Target != "" {
				fallbackTarget = it.Target
			}
			dedupKey := it.ChangeType + "\x00" + it.URL + "\x00" + it.Summary
			if idx, ok := seen[dedupKey]; ok {
				itemRowIDs[idx] = append(itemRowIDs[idx], r.id)
				continue
			}
			seen[dedupKey] = len(items)
			items = append(items, it)
			itemRowIDs = append(itemRowIDs, []string{r.id})
		}
		if len(items) == 0 {
			return []tgPackedMessage{{text: rows[0].message, rowIDs: allIDs}}
		}
		label := b.targetLabel(ctx, targetID, "")
		if label == "" {
			label = fallbackTarget
		}
		chunks := formatMonitorBatch(label, items, itemRowIDs)
		if len(unparsedIDs) > 0 && len(chunks) > 0 {
			chunks[0].rowIDs = append(chunks[0].rowIDs, unparsedIDs...)
		}
		return chunks

	case "finding":
		var items []tgFindingItem
		var itemRowIDs [][]string
		var unparsedIDs []string
		seen := make(map[string]int)
		fallbackTarget := ""
		for _, r := range rows {
			var it tgFindingItem
			if r.itemJSON == "" || json.Unmarshal([]byte(r.itemJSON), &it) != nil {
				unparsedIDs = append(unparsedIDs, r.id)
				continue
			}
			if fallbackTarget == "" && it.Target != "" {
				fallbackTarget = it.Target
			}
			dedupKey := it.Severity + "\x00" + it.Type + "\x00" + it.URL + "\x00" + it.Parameter
			if idx, ok := seen[dedupKey]; ok {
				itemRowIDs[idx] = append(itemRowIDs[idx], r.id)
				continue
			}
			seen[dedupKey] = len(items)
			items = append(items, it)
			itemRowIDs = append(itemRowIDs, []string{r.id})
		}
		if len(items) == 0 {
			return []tgPackedMessage{{text: rows[0].message, rowIDs: allIDs}}
		}
		label := b.targetLabel(ctx, targetID, "")
		if label == "" {
			label = fallbackTarget
		}
		chunks := formatFindingBatch(label, items, itemRowIDs)
		if len(unparsedIDs) > 0 && len(chunks) > 0 {
			chunks[0].rowIDs = append(chunks[0].rowIDs, unparsedIDs...)
		}
		return chunks
	}
	return []tgPackedMessage{{text: rows[0].message, rowIDs: allIDs}}
}

func packBatchMessages(header, destLabel string, lines []string, itemRowIDs [][]string) []tgPackedMessage {
	if destLabel == "" {
		destLabel = "Changes"
	}
	if len(lines) == 0 {
		var all []string
		for _, ids := range itemRowIDs {
			all = append(all, ids...)
		}
		return []tgPackedMessage{{text: header, rowIDs: all}}
	}
	total := len(lines)
	limit := total
	if limit > tgBatchMaxItems {
		limit = tgBatchMaxItems
	}
	var msgs []tgPackedMessage
	idx := 0
	for msgNum := 0; msgNum < tgBatchMaxMsgs && idx < limit; msgNum++ {
		h := header
		if msgNum > 0 {
			h = header + " (cont.)"
		}
		var sb strings.Builder
		sb.WriteString(h)
		usedRunes := len([]rune(h))
		added := 0
		var chunkIDs []string
		for idx < limit {
			line := lines[idx]
			lineRunes := 1 + len([]rune(line))
			reserve := 0
			if msgNum == tgBatchMaxMsgs-1 && idx < total-1 {
				reserve = 40
			}
			if added > 0 && usedRunes+lineRunes+reserve > tgBatchMaxRunes {
				break
			}
			sb.WriteByte('\n')
			sb.WriteString(line)
			usedRunes += lineRunes
			if idx < len(itemRowIDs) {
				chunkIDs = append(chunkIDs, itemRowIDs[idx]...)
			}
			added++
			idx++
		}
		msgs = append(msgs, tgPackedMessage{text: sb.String(), rowIDs: chunkIDs})
	}
	if remaining := total - idx; remaining > 0 && len(msgs) > 0 {
		last := &msgs[len(msgs)-1]
		last.text += fmt.Sprintf("\n… +%d more in %s", remaining, destLabel)
		for j := idx; j < len(itemRowIDs); j++ {
			last.rowIDs = append(last.rowIDs, itemRowIDs[j]...)
		}
	}
	return msgs
}

func formatStatusTransition(it tgStatusItem) string {
	if it.OldCode > 0 && it.NewCode > 0 {
		return fmt.Sprintf("%d → %d", it.OldCode, it.NewCode)
	}
	oldStr := it.OldText
	if it.OldCode > 0 {
		oldStr = strconv.Itoa(it.OldCode)
	}
	newStr := it.NewText
	if it.NewCode > 0 {
		newStr = strconv.Itoa(it.NewCode)
	}
	if oldStr != "" && newStr != "" {
		return oldStr + " → " + newStr
	}
	if newStr != "" {
		return newStr
	}
	return oldStr
}

func formatHTTPStatusBatch(label string, items []tgStatusItem, itemRowIDs [][]string) []tgPackedMessage {
	base := "HTTP status"
	if label != "" {
		base += " · " + label
	}
	if len(items) == 1 {
		it := items[0]
		trans := formatStatusTransition(it)
		line := trans
		if it.URL != "" {
			line = fmt.Sprintf("%s  %s", it.URL, trans)
		}
		var ids []string
		if len(itemRowIDs) > 0 {
			ids = itemRowIDs[0]
		}
		return []tgPackedMessage{{text: base + "\n" + line, rowIDs: ids}}
	}
	header := fmt.Sprintf("%s (%d)", base, len(items))
	lines := make([]string, 0, len(items))
	for _, it := range items {
		trans := formatStatusTransition(it)
		if it.URL != "" {
			lines = append(lines, fmt.Sprintf("• %s  %s", it.URL, trans))
		} else {
			lines = append(lines, "• "+trans)
		}
	}
	return packBatchMessages(header, "Changes", lines, itemRowIDs)
}

func formatScopeLine(it tgScopeItem) string {
	switch strings.ToLower(strings.TrimSpace(it.EventType)) {
	case "added":
		return "+ " + it.Identifier + " (pending)"
	case "modified":
		return "~ " + it.Identifier + " (modified)"
	case "removed":
		return "- " + it.Identifier + " (removed)"
	case "rule_added":
		return "⊘ " + it.Identifier + " (deny rule added)"
	case "rule_removed":
		return "✓ " + it.Identifier + " (deny rule withdrawn)"
	default:
		return "• " + it.Identifier + " (" + it.EventType + ")"
	}
}

func formatScopeBatch(targetName, progName string, items []tgScopeItem, itemRowIDs [][]string) []tgPackedMessage {
	header := "Scope"
	switch {
	case targetName != "" && progName != "":
		header = fmt.Sprintf("Scope · %s (%s)", targetName, progName)
	case targetName != "":
		header = "Scope · " + targetName
	case progName != "":
		header = "Scope · " + progName
	}
	if len(items) >= 2 {
		header = fmt.Sprintf("%s (%d)", header, len(items))
	}
	lines := make([]string, 0, len(items))
	for _, it := range items {
		lines = append(lines, formatScopeLine(it))
	}
	return packBatchMessages(header, "Changes", lines, itemRowIDs)
}

func formatMonitorBatch(label string, items []tgMonitorItem, itemRowIDs [][]string) []tgPackedMessage {
	header := "Security drift"
	if label != "" {
		header += " · " + label
	}
	if len(items) >= 2 {
		header = fmt.Sprintf("%s (%d)", header, len(items))
	}
	lines := make([]string, 0, len(items))
	for _, it := range items {
		if it.URL != "" && it.Summary != "" {
			lines = append(lines, fmt.Sprintf("• %s — %s", it.URL, it.Summary))
		} else if it.Summary != "" {
			lines = append(lines, "• "+it.Summary)
		} else if it.URL != "" {
			lines = append(lines, "• "+it.URL)
		}
	}
	return packBatchMessages(header, "Changes", lines, itemRowIDs)
}

func formatFindingBatch(label string, items []tgFindingItem, itemRowIDs [][]string) []tgPackedMessage {
	header := "Verified finding"
	if len(items) >= 2 {
		header = "Verified findings"
	}
	if label != "" {
		header += " · " + label
	}
	if len(items) >= 2 {
		header = fmt.Sprintf("%s (%d)", header, len(items))
	}
	lines := make([]string, 0, len(items))
	for _, it := range items {
		sev := strings.ToUpper(strings.TrimSpace(it.Severity))
		if sev == "" {
			sev = "INFO"
		}
		line := fmt.Sprintf("• [%s] %s — %s", sev, it.Type, it.URL)
		if it.Parameter != "" {
			line += " (param: " + it.Parameter + ")"
		}
		lines = append(lines, line)
	}
	return packBatchMessages(header, "Findings", lines, itemRowIDs)
}

func (b *TelegramBot) NotifyScanStarted(taskID, targetID, domain string) {
	b.scans.Store(taskID, time.Now())
	text := "Scan started\nTarget: " + b.targetLabel(context.Background(), targetID, domain) + "\nTask: " + shortBotID(taskID)
	b.enqueue("scan_started", "scan:start:"+taskID, text, b.scanKeyboard(targetID))
}

func (b *TelegramBot) NotifyPhaseFinished(taskID, targetID, domain, phase, status string, duration time.Duration, progress, total int) {
	text := fmt.Sprintf("Scan phase %s\nTarget: %s\nPhase: %s\nProgress: %d/%d\nDuration: %s",
		strings.ReplaceAll(status, "_", " "), b.targetLabel(context.Background(), targetID, domain), phase, progress, total, shortDuration(duration))
	b.enqueue("phase_finished", "scan:phase:"+taskID+":"+phase+":"+status, text, b.scanKeyboard(targetID))
	b.enqueueValidFindingsSince(targetID, b.findingSweepStart(taskID, duration))
}

func (b *TelegramBot) NotifyScanFinished(taskID, targetID, domain, status string, duration time.Duration, stats map[string]int) {
	text := fmt.Sprintf("Scan %s\nTarget: %s\nDuration: %s\nSubdomains: %d · Alive: %d\nVerified findings: %d\nNative: %d · Nuclei: %d · Backups: %d · Redirects: %d · JS: %d",
		status, b.targetLabel(context.Background(), targetID, domain), shortDuration(duration), stats["subdomains"], stats["alive"], stats["verified"],
		stats["vulns"], stats["nuclei"], stats["backups"], stats["redirects"], stats["js"])
	b.enqueue("scan_finished", "scan:finish:"+taskID+":"+status, text, b.scanKeyboard(targetID))
	b.enqueueValidFindingsSince(targetID, b.findingSweepStart(taskID, duration))
	b.scans.Delete(taskID)
}

func (b *TelegramBot) findingSweepStart(taskID string, fallbackDuration time.Duration) time.Time {
	if started, ok := b.scans.Load(taskID); ok {
		if value, valid := started.(time.Time); valid {
			return value.Add(-2 * time.Second)
		}
	}
	return time.Now().Add(-fallbackDuration - 2*time.Second)
}

func (b *TelegramBot) NotifyNewVuln(findingID, targetID, domain, vulnType, severity, rawURL, parameter string) {
	label := b.targetLabel(context.Background(), targetID, domain)
	item := tgFindingItem{
		Target:    label,
		Severity:  strings.ToUpper(strings.TrimSpace(severity)),
		Type:      vulnType,
		URL:       rawURL,
		Parameter: parameter,
	}
	fallback := formatFindingBatch(label, []tgFindingItem{item}, nil)[0].text
	batchKey := "finding:" + targetID
	if targetID == "" {
		batchKey = ""
	}
	b.enqueueBatched("finding", "finding:"+findingID, batchKey, targetID, fallback, item, b.findingKeyboard(targetID), b.findingCoalesceDelay())
}

func (b *TelegramBot) NotifyMonitorChange(targetID, domain, changeType, title, rawURL, oldVal, newVal string, eventID ...string) {
	// Defense-in-depth: hash-only JS/CSS churn and external stylesheet diffs
	// stay in monitoring_changes / Diff viewer and never page Telegram.
	ct := strings.ToLower(strings.TrimSpace(changeType))
	if ct == "js_change" || ct == "css_change" || strings.HasPrefix(ct, "security:stylesheet") {
		return
	}
	label := b.targetLabel(context.Background(), targetID, domain)
	summary := formatMonitorSummary(changeType, title, oldVal, newVal)
	item := tgMonitorItem{
		Target:     label,
		ChangeType: changeType,
		URL:        strings.TrimSpace(rawURL),
		Summary:    summary,
	}
	fallback := formatMonitorBatch(label, []tgMonitorItem{item}, nil)[0].text
	key := "monitor:" + targetID + ":" + changeType + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if len(eventID) > 0 && eventID[0] != "" {
		// Use the change id so retries and duplicate broadcasts dedupe on the
		// outbox unique key instead of minting a fresh event every call (B10).
		key = "monitor:" + eventID[0]
	}
	batchKey := "monitoring:" + targetID
	if targetID == "" {
		batchKey = ""
	}
	b.enqueueBatched("monitoring", key, batchKey, targetID, fallback, item, b.alertKeyboard(targetID), b.coalesceWindow)
}

// NotifyHTTPStatus delivers an actual HTTP status transition. It has its own
// per-chat switch, so an operator can mute routine monitoring drift and still
// receive status changes, or the reverse.
func (b *TelegramBot) NotifyHTTPStatus(targetID, domain, changeType, title, rawURL, oldVal, newVal, eventID string) {
	label := b.targetLabel(context.Background(), targetID, domain)
	oldCode := extractHTTPStatusCode(oldVal)
	newCode := extractHTTPStatusCode(newVal)
	item := tgStatusItem{
		Target:  label,
		URL:     strings.TrimSpace(rawURL),
		OldCode: oldCode,
		NewCode: newCode,
	}
	if oldCode == 0 {
		item.OldText = strings.TrimSpace(strings.TrimPrefix(oldVal, "HTTP "))
	}
	if newCode == 0 {
		item.NewText = strings.TrimSpace(strings.TrimPrefix(newVal, "HTTP "))
	}
	fallback := formatHTTPStatusBatch(label, []tgStatusItem{item}, nil)[0].text
	key := "http-status:" + eventID
	if eventID == "" {
		key = "http-status:" + targetID + ":" + changeType + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	batchKey := "http_status:" + targetID
	if targetID == "" {
		batchKey = ""
	}
	b.enqueueBatched("http_status", key, batchKey, targetID, fallback, item, b.alertKeyboard(targetID), b.coalesceWindow)
}

// NotifyProgramScope delivers an upstream program scope change. It uses a
// stable event key so the outbox deduplicates a whole reconciliation window.
func (b *TelegramBot) NotifyProgramScope(targetID, domain, programID, eventType, identifier, eventID string) {
	ctx := context.Background()
	label := b.targetLabel(ctx, targetID, domain)
	progName := b.programLabel(ctx, programID)
	item := tgScopeItem{
		Target:      label,
		ProgramID:   programID,
		ProgramName: progName,
		EventType:   eventType,
		Identifier:  identifier,
	}
	fallback := formatScopeBatch(label, progName, []tgScopeItem{item}, nil)[0].text
	key := "program-scope:" + eventID
	if eventID == "" {
		key = "program-scope:" + programID + ":" + eventType + ":" + identifier
	}
	batchKey := "program_scope:" + targetID + ":" + programID
	b.enqueueBatched("program_scope", key, batchKey, targetID, fallback, item, b.alertKeyboard(targetID), b.coalesceWindow)
}

// NotifyWatchScanStarted reports the start of a breadth/watch round. It is a
// separate template from the deep scan alert: the operator reads the two tiers
// as different workloads, and a watch round runs on its own 30-minute rhythm.
func (b *TelegramBot) NotifyWatchScanStarted(taskID, targetID, domain string) {
	text := "Watch round started\nTarget: " + b.targetLabel(context.Background(), targetID, domain) + "\nTask: " + shortBotID(taskID)
	b.enqueue("watch_scan_started", "watch:start:"+taskID, text, b.scanKeyboard(targetID))
}

// NotifyWatchScanFinished reports the end of a breadth/watch round with the
// host counts it produced. It stays off by default per chat: with many watch
// projects this message repeats every round.
func (b *TelegramBot) NotifyWatchScanFinished(taskID, targetID, domain, status string, duration time.Duration, stats map[string]int, skippedSummary string) {
	text := fmt.Sprintf("Watch round %s\nTarget: %s\nDuration: %s\nHosts seen: %d · Alive: %d\nNew hosts: %d · Scope landed: %d",
		status, b.targetLabel(context.Background(), targetID, domain), shortDuration(duration), stats["subdomains"], stats["alive"],
		stats["new_hosts"], stats["landed"])
	if skippedSummary != "" {
		text += "\n" + skippedSummary
	}
	b.enqueue("watch_scan_finished", "watch:finish:"+taskID+":"+status, text, b.scanKeyboard(targetID))
}

// NotifyScopeLanded delivers the grouped scope-landed alert. The scheduler
// owns the event key, so the outbox deduplicates the window: one message per
// tick window across every watch project, never one message per host.
func (b *TelegramBot) NotifyScopeLanded(eventKey, summary string, hosts []string) {
	text := "New eligible scope\n" + summary
	if len(hosts) > 0 {
		shown := hosts
		extra := 0
		if len(shown) > tgBatchMaxItems {
			extra = len(shown) - tgBatchMaxItems
			shown = shown[:tgBatchMaxItems]
		}
		text += "\n" + strings.Join(shown, "\n")
		if extra > 0 {
			text += fmt.Sprintf("\n… +%d more in Changes", extra)
		}
	}
	b.enqueue("scope_landed", eventKey, text, nil)
}

// NotifyNewHosts delivers the grouped first-seen-alive alert for one watch
// round. It is ON by default per chat; the separate per-chat switch lets an
// operator mute this one high-volume signal without losing scope alerts.
func (b *TelegramBot) NotifyNewHosts(eventKey, summary string, hosts []string, targetID string) {
	label := ""
	if targetID != "" {
		label = b.targetLabel(context.Background(), targetID, "")
	}
	var header string
	if label != "" {
		if len(hosts) > 0 {
			header = fmt.Sprintf("New hosts · %s (+%d)", label, len(hosts))
		} else if summary != "" {
			header = fmt.Sprintf("New hosts · %s\n%s", label, summary)
		} else {
			header = "New hosts · " + label
		}
	} else if summary != "" {
		header = "New hosts up\n" + summary
	} else {
		header = "New hosts up"
	}
	text := header
	if len(hosts) > 0 {
		shown := hosts
		extra := 0
		if len(shown) > tgBatchMaxItems {
			extra = len(shown) - tgBatchMaxItems
			shown = shown[:tgBatchMaxItems]
		}
		lines := make([]string, 0, len(shown))
		for _, h := range shown {
			lines = append(lines, "• "+h)
		}
		text += "\n" + strings.Join(lines, "\n")
		if extra > 0 {
			text += fmt.Sprintf("\n… +%d more in Changes", extra)
		}
	}
	b.enqueue("new_host", eventKey, text, b.alertKeyboard(targetID))
}

// Some first-class finding stores (verified Nuclei, backup exposure and open
// redirect) predate new_vuln_finding broadcasts. Sweep only the just-finished
// phase window and rely on the outbox's row-id event key for exact-once delivery.
func (b *TelegramBot) enqueueValidFindingsSince(targetID string, since time.Time) {
	sinceSQL := since.UTC().Format("2006-01-02 15:04:05")
	label := b.targetLabel(context.Background(), targetID, "")
	type found struct{ id, typ, severity, rawURL, param, qualifier string }
	var all []found
	queries := []struct {
		query string
		args  []any
	}{
		{`SELECT id,type,severity,url,COALESCE(parameter,''),'verified' FROM vuln_findings
			WHERE target_id=? AND COALESCE(status,'finding')='finding' AND COALESCE(triage,'')<>'false_positive' AND created_at>=?`, []any{targetID, sinceSQL}},
		// A candidate promoted during verification keeps its old created_at,
		// so the sweep must look at the promotion timestamp instead (B7).
		{`SELECT id,type,severity,url,COALESCE(parameter,''),'promoted' FROM vuln_findings
			WHERE target_id=? AND COALESCE(status,'finding')='finding' AND COALESCE(triage,'')<>'false_positive'
			  AND verified_at>=? AND first_verified_notified=0`, []any{targetID, sinceSQL}},
		{`SELECT id,template_name,severity,matched_url,'',COALESCE(verification,'unverified') FROM nuclei_findings
			WHERE target_id=? AND verification='verified' AND verified_at>=?`, []any{targetID, sinceSQL}},
		{`SELECT id,'open_redirect','medium',url,COALESCE(parameter,''),'verified' FROM open_redirect_findings
			WHERE target_id=? AND verified=1 AND COALESCE(status,'finding')='finding' AND created_at>=?`, []any{targetID, sinceSQL}},
		{`SELECT id,'backup_exposure','high',url,'','content-validated' FROM backup_findings
			WHERE target_id=? AND created_at>=?`, []any{targetID, sinceSQL}},
		{`SELECT id,type,severity,COALESCE((SELECT url FROM js_files WHERE id=js_findings.js_file_id),''),'','verified' FROM js_findings
			WHERE target_id=? AND verified=1 AND created_at>=?`, []any{targetID, sinceSQL}},
	}
	for _, q := range queries {
		rows, err := b.h.db.Query(q.query, q.args...)
		if err != nil {
			b.logDBError("telegram findings sweep query", err)
			continue
		}
		for rows.Next() {
			var f found
			if err := rows.Scan(&f.id, &f.typ, &f.severity, &f.rawURL, &f.param, &f.qualifier); err != nil {
				b.logDBError("telegram findings sweep scan", err)
				continue
			}
			all = append(all, f)
		}
		if err := rows.Err(); err != nil {
			b.logDBError("telegram findings sweep rows", err)
		}
		rows.Close()
	}
	batchKey := "finding:" + targetID
	if targetID == "" {
		batchKey = ""
	}
	delay := b.findingCoalesceDelay()
	kb := b.findingKeyboard(targetID)
	for _, f := range all {
		item := tgFindingItem{
			Target:    label,
			Severity:  strings.ToUpper(strings.TrimSpace(f.severity)),
			Type:      f.typ,
			URL:       f.rawURL,
			Parameter: f.param,
			Proof:     f.qualifier,
		}
		fallback := formatFindingBatch(label, []tgFindingItem{item}, nil)[0].text
		b.enqueueBatched("finding", "finding:"+f.id, batchKey, targetID, fallback, item, kb, delay)
		if f.qualifier == "promoted" {
			if _, err := b.h.db.Exec(`UPDATE vuln_findings SET first_verified_notified=1 WHERE id=?`, f.id); err != nil {
				b.logDBError("telegram mark finding promoted notified", err)
			}
		}
	}
}

func (b *TelegramBot) scanKeyboard(targetID string) *tgInlineKeyboard {
	return &tgInlineKeyboard{Rows: [][]tgInlineButton{
		{{Text: "Target", CallbackData: "target:" + targetID}, {Text: "Skip phase", CallbackData: "skip:" + targetID}},
		{{Text: "Pause", CallbackData: "pause:" + targetID}, {Text: "Resume", CallbackData: "resume:" + targetID}, {Text: "Cancel", CallbackData: "cancel:" + targetID}},
	}}
}

func (b *TelegramBot) alertKeyboard(targetID string) *tgInlineKeyboard {
	if targetID == "" {
		return nil
	}
	return &tgInlineKeyboard{Rows: [][]tgInlineButton{
		{{Text: "Target", CallbackData: "target:" + targetID}},
	}}
}

func (b *TelegramBot) findingKeyboard(targetID string) *tgInlineKeyboard {
	return &tgInlineKeyboard{Rows: [][]tgInlineButton{{{Text: "Latest findings", CallbackData: "findings:" + targetID}, {Text: "Target", CallbackData: "target:" + targetID}}}}
}

func (b *TelegramBot) logDBError(op string, err error) {
	if err == nil {
		return
	}
	if b != nil && b.h != nil && b.h.logger != nil {
		b.h.logger.Error(op, "error", err)
	}
}

func (b *TelegramBot) targetLabel(ctx context.Context, targetID, fallbackDomain string) string {
	if b != nil && b.h != nil && b.h.db != nil && targetID != "" {
		if ctx == nil {
			ctx = context.Background()
		}
		var name, domain string
		err := b.h.db.QueryRowContext(ctx, `SELECT COALESCE(TRIM(name),''), COALESCE(domain,'') FROM targets WHERE id=?`, targetID).Scan(&name, &domain)
		if err == nil {
			if name != "" {
				return capRunes(name, 60)
			}
			if domain != "" {
				return displayDomain(domain)
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			b.logDBError("telegram target label lookup", err)
		}
	}
	trimmed := strings.TrimSpace(fallbackDomain)
	if trimmed == "" {
		return ""
	}
	if strings.ContainsAny(trimmed, ",;\n\r\t") || strings.Contains(trimmed, "://") {
		return displayDomain(trimmed)
	}
	return capRunes(trimmed, 60)
}

func (b *TelegramBot) programLabel(ctx context.Context, programID string) string {
	if b != nil && b.h != nil && b.h.db != nil && programID != "" {
		if ctx == nil {
			ctx = context.Background()
		}
		var label string
		err := b.h.db.QueryRowContext(ctx,
			`SELECT COALESCE(NULLIF(TRIM(name),''), COALESCE(NULLIF(TRIM(handle),''), '')) FROM bounty_programs WHERE id=?`,
			programID).Scan(&label)
		if err == nil && label != "" {
			return capRunes(label, 60)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			b.logDBError("telegram program label lookup", err)
		}
	}
	return shortBotID(programID)
}

var httpStatusCodeRE = regexp.MustCompile(`\b([1-5][0-9]{2})\b`)

func extractHTTPStatusCode(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if n, err := strconv.Atoi(raw); err == nil && n >= 100 && n <= 599 {
		return n
	}
	if idx := strings.Index(strings.ToLower(raw), "status="); idx >= 0 {
		rest := raw[idx+len("status="):]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 {
			if n, err := strconv.Atoi(rest[:end]); err == nil && n >= 100 && n <= 599 {
				return n
			}
		}
		return 0
	}
	if m := httpStatusCodeRE.FindStringSubmatch(raw); len(m) == 2 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	return 0
}

func stripMonitorPrefix(s, prefix string) string {
	s = strings.TrimSpace(s)
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return strings.TrimSpace(s[len(prefix):])
	}
	return s
}

func stripMonitorSuffix(s, suffix string) string {
	s = strings.TrimSpace(s)
	if len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix) {
		return strings.TrimSpace(s[:len(s)-len(suffix)])
	}
	return s
}

func isHexHash(s string) bool {
	n := len(s)
	if n != 32 && n != 40 && n != 64 {
		return false
	}
	for i := range n {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isShortNonHash(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > 48 || isHexHash(s) {
		return false
	}
	return true
}

func formatMonitorSummary(changeType, title, oldVal, newVal string) string {
	ct := strings.ToLower(strings.TrimSpace(changeType))
	oldVal = strings.TrimSpace(oldVal)
	newVal = strings.TrimSpace(newVal)
	title = strings.TrimSpace(title)

	switch {
	case ct == "security_header_removed" || ct == "header_regression" || strings.HasSuffix(ct, "_header_removed"):
		header := stripMonitorSuffix(stripMonitorSuffix(oldVal, " present"), " removed")
		if header == "" {
			header = stripMonitorSuffix(newVal, " removed")
		}
		if header != "" {
			return header + " header removed"
		}
		if title != "" {
			return title
		}
		return "Security header removed"

	case ct == "security:script_added":
		src := stripMonitorPrefix(newVal, "added script:")
		if src == "" {
			src = title
		}
		if src != "" {
			return "External script added: " + src
		}
		return "External script added"

	case ct == "security:script_removed":
		src := stripMonitorPrefix(oldVal, "removed script:")
		if src == "" {
			src = stripMonitorPrefix(newVal, "removed script:")
		}
		if src == "" {
			src = title
		}
		if src != "" {
			return "External script removed: " + src
		}
		return "External script removed"

	case ct == "security:sri_removed":
		src := stripMonitorPrefix(oldVal, "removed sri:")
		if src == "" {
			src = stripMonitorPrefix(newVal, "removed sri:")
		}
		if src == "" {
			src = title
		}
		if src != "" {
			return "SRI removed: " + src
		}
		return "SRI removed"

	case ct == "security:form_action_changed":
		if oldVal != "" && newVal != "" {
			return "Form action: " + oldVal + " → " + newVal
		}
		if newVal != "" {
			return "Form action: " + stripMonitorPrefix(newVal, "changed form:")
		}
		if title != "" {
			return title
		}
		return "Form action changed"

	case ct == "security:form_added", ct == "security:form_removed",
		ct == "security:iframe_added", ct == "security:iframe_removed",
		ct == "security:hidden_added", ct == "security:hidden_removed",
		ct == "security:link_added", ct == "security:link_removed":
		kindAction := strings.TrimPrefix(ct, "security:")
		labelMap := map[string]string{
			"form_added":     "Form added",
			"form_removed":   "Form removed",
			"iframe_added":   "Iframe added",
			"iframe_removed": "Iframe removed",
			"hidden_added":   "Hidden field added",
			"hidden_removed": "Hidden field removed",
			"link_added":     "External link added",
			"link_removed":   "External link removed",
		}
		label := labelMap[kindAction]
		val := newVal
		if val == "" {
			val = oldVal
		}
		for _, pfx := range []string{"added form:", "removed form:", "added iframe:", "removed iframe:", "added hidden:", "removed hidden:", "added link:", "removed link:"} {
			val = stripMonitorPrefix(val, pfx)
		}
		if val != "" {
			return label + ": " + capRunes(val, 120)
		}
		return label
	}

	base := title
	if base == "" || strings.EqualFold(base, "Change detected") {
		if cleanType := strings.ReplaceAll(strings.TrimPrefix(changeType, "security:"), "_", " "); cleanType != "" {
			base = cleanType
		}
	}
	if oldVal != "" && newVal != "" && oldVal != newVal && isShortNonHash(oldVal) && isShortNonHash(newVal) {
		return base + " (" + oldVal + " → " + newVal + ")"
	}
	if newVal != "" && !isHexHash(newVal) {
		if base != "" {
			return base + ": " + capRunes(newVal, 120)
		}
		return capRunes(newVal, 120)
	}
	if oldVal != "" && !isHexHash(oldVal) {
		if base != "" {
			return base + ": " + capRunes(oldVal, 120)
		}
		return capRunes(oldVal, 120)
	}
	return base
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func minInt(a, c int) int {
	if a < c {
		return a
	}
	return c
}

func shortBotID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func shortDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func capRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}

func displayDomain(domain string) string {
	tokens := strings.FieldsFunc(domain, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(tokens) == 0 {
		return ""
	}
	first := tokens[0]
	if strings.Contains(first, "://") {
		if u, err := url.Parse(first); err == nil && u.Host != "" {
			first = u.Host
		}
	}
	first = strings.TrimRight(first, "/")
	if len(tokens) > 1 {
		suffix := fmt.Sprintf(" (+%d more)", len(tokens)-1)
		maxFirst := 60 - len([]rune(suffix))
		if maxFirst < 8 {
			maxFirst = 8
		}
		return capRunes(first, maxFirst) + suffix
	}
	return capRunes(first, 60)
}
