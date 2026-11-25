package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
)

func telegramAPIMock(t *testing.T, messages *[]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		switch {
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"id":42,"username":"reconner_test_bot"}}`))
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			*messages = append(*messages, payload)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		}
	}))
}

func TestTelegramTokenIsValidatedMaskedAndEncrypted(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg.SessionSecret = "unit-test-session-secret"
	bot := NewTelegramBot(h)
	var messages []map[string]any
	server := telegramAPIMock(t, &messages)
	defer server.Close()
	bot.apiBase = server.URL

	token := "123456789:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
	enabled := true
	if err := bot.Configure(context.Background(), &token, &enabled); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := h.db.QueryRow(`SELECT encrypted_bot_token FROM telegram_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token || !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("bot token was not encrypted at rest: %q", stored)
	}
	state, err := bot.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Configured || !state.Enabled || state.BotUsername != "reconner_test_bot" || state.MaskedToken == token {
		t.Fatalf("unsafe or incomplete state: %+v", state)
	}
	if _, err := h.db.Exec(`UPDATE telegram_config SET last_update_id=77 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	disabled := false
	if err := bot.Configure(context.Background(), nil, &disabled); err != nil {
		t.Fatal(err)
	}
	var lastUpdateID int64
	_ = h.db.QueryRow(`SELECT last_update_id FROM telegram_config WHERE id=1`).Scan(&lastUpdateID)
	if lastUpdateID != 77 {
		t.Fatalf("toggling the existing bot reset its update cursor: %d", lastUpdateID)
	}
	replacement := "987654321:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
	if err := bot.Configure(context.Background(), &replacement, &enabled); err != nil {
		t.Fatal(err)
	}
	_ = h.db.QueryRow(`SELECT last_update_id FROM telegram_config WHERE id=1`).Scan(&lastUpdateID)
	if lastUpdateID != 0 {
		t.Fatalf("a replacement bot inherited the previous bot's update cursor: %d", lastUpdateID)
	}
}

func TestTelegramOutboxFansOutAndHonorsPerChatPreferences(t *testing.T) {
	h, _ := newIsoHandler(t)
	bot := NewTelegramBot(h)
	if _, err := h.db.Exec(`INSERT INTO telegram_config(id,encrypted_bot_token,enabled) VALUES(1,'test-token',1)`); err != nil {
		t.Fatal(err)
	}
	first, err := bot.AddChat(context.Background(), TelegramChat{ChatID: "1001", Label: "viewer", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := bot.AddChat(context.Background(), TelegramChat{ChatID: "-1002002", Label: "ops", Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	// New chats start quiet for routine phase messages. Opt in explicitly:
	// this test asserts per-chat preference fanout, not the defaults.
	first.NotifyPhaseFinished = true
	if err := bot.UpdateChat(context.Background(), first.ID, first); err != nil {
		t.Fatal(err)
	}
	second.NotifyFindings = false
	second.NotifyPhaseFinished = true
	if err := bot.UpdateChat(context.Background(), second.ID, second); err != nil {
		t.Fatal(err)
	}

	bot.NotifyNewVuln("finding-1", "target-1", "example.com", "sqli", "medium", "https://example.com/?id=1", "id")
	bot.NotifyPhaseFinished("task-1", "target-1", "example.com", "sqli", "completed", 0, 3, 5)
	bot.NotifyPhaseFinished("task-1", "target-1", "example.com", "origin_ip", "blocked", 0, 4, 5)
	bot.NotifyPhaseFinished("task-1", "target-1", "example.com", "nuclei", "skipped", 0, 5, 5)

	var findingRows, phaseRows int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='finding'`).Scan(&findingRows)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='phase_finished'`).Scan(&phaseRows)
	if findingRows != 1 || phaseRows != 6 {
		t.Fatalf("preference fanout wrong: findings=%d phases=%d", findingRows, phaseRows)
	}
	// Exact-once per chat/event: replaying the same callbacks cannot duplicate.
	bot.NotifyNewVuln("finding-1", "target-1", "example.com", "sqli", "medium", "https://example.com/?id=1", "id")
	bot.NotifyPhaseFinished("task-1", "target-1", "example.com", "sqli", "completed", 0, 3, 5)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='finding'`).Scan(&findingRows)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='phase_finished'`).Scan(&phaseRows)
	if findingRows != 1 || phaseRows != 6 {
		t.Fatalf("outbox dedup failed: findings=%d phases=%d", findingRows, phaseRows)
	}
	var blockedMessage, skippedMessage string
	_ = h.db.QueryRow(`SELECT message FROM telegram_outbox WHERE event_key='scan:phase:task-1:origin_ip:blocked' LIMIT 1`).Scan(&blockedMessage)
	_ = h.db.QueryRow(`SELECT message FROM telegram_outbox WHERE event_key='scan:phase:task-1:nuclei:skipped' LIMIT 1`).Scan(&skippedMessage)
	if !strings.Contains(blockedMessage, "Scan phase blocked") || !strings.Contains(skippedMessage, "Scan phase skipped") {
		t.Fatalf("terminal phase notifications lost status: blocked=%q skipped=%q", blockedMessage, skippedMessage)
	}
	_, _ = h.db.Exec(`UPDATE telegram_config SET enabled=0 WHERE id=1`)
	bot.NotifyNewVuln("finding-while-disabled", "target-1", "example.com", "xss", "high", "https://example.com/x", "q")
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='finding'`).Scan(&findingRows)
	if findingRows != 1 {
		t.Fatalf("disabled bot accumulated a surprise delivery backlog: findings=%d", findingRows)
	}
	if first.Role != "viewer" {
		t.Fatalf("chat role changed unexpectedly: %+v", first)
	}
}

func TestTelegramOutboxDeliversToEveryConfiguredChat(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg.SessionSecret = "unit-test-session-secret"
	bot := NewTelegramBot(h)
	bot.coalesceWindow = 0
	var messages []map[string]any
	server := telegramAPIMock(t, &messages)
	defer server.Close()
	bot.apiBase = server.URL
	token := "123456789:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
	enabled := true
	if err := bot.Configure(context.Background(), &token, &enabled); err != nil {
		t.Fatal(err)
	}
	for _, chatID := range []string{"1001", "-1002002"} {
		if _, err := bot.AddChat(context.Background(), TelegramChat{ChatID: chatID, Role: "viewer"}); err != nil {
			t.Fatal(err)
		}
	}
	bot.NotifyNewVuln("finding-1", "target-1", "example.com", "sqli", "critical", "https://example.com/?id=1", "id")
	bot.drainOutbox(context.Background())
	if len(messages) != 2 {
		t.Fatalf("expected one delivery per chat, got %d", len(messages))
	}
	var sent, pending int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE status='sent'`).Scan(&sent)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE status='pending'`).Scan(&pending)
	if sent != 2 || pending != 0 {
		t.Fatalf("unexpected delivery state: sent=%d pending=%d", sent, pending)
	}
}

func TestTelegramAdminCanCreateAndEditTarget(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg = &config.Config{SessionSecret: "test"}
	bot := NewTelegramBot(h)
	target, err := bot.createTelegramTarget(context.Background(), "https://example.com/app", "Example")
	if err != nil {
		t.Fatal(err)
	}
	if target.Name != "Example" || target.Kind != "web" || target.Domain != "https://example.com/app" {
		t.Fatalf("unexpected target: %+v", target)
	}
	if err := bot.editTelegramTarget(context.Background(), target, []string{"name=Renamed", "priority=high", "notes=telegram"}); err != nil {
		t.Fatal(err)
	}
	updated, err := bot.resolveTelegramTarget(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Renamed" || updated.Priority != "high" {
		t.Fatalf("target edit did not persist: %+v", updated)
	}
}

func TestTelegramTargetManagementRejectsUnsupportedNetworkScopes(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg = &config.Config{SessionSecret: "test"}
	bot := NewTelegramBot(h)
	ctx := context.Background()

	for _, scope := range []string{"10.0.0.0/24", "example.com,10.0.0.1"} {
		if _, err := bot.createTelegramTarget(ctx, scope, "unsupported"); err == nil || !strings.Contains(err.Error(), "network/CIDR") {
			t.Fatalf("create scope %q error=%v, want explicit network rejection", scope, err)
		}
	}
	var count int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unsupported Telegram create persisted %d target(s)", count)
	}

	target, err := bot.createTelegramTarget(ctx, "example.org", "web")
	if err != nil {
		t.Fatal(err)
	}
	if err := bot.editTelegramTarget(ctx, target, []string{"name=must-not-commit", "scope=192.0.2.0/24"}); err == nil || !strings.Contains(err.Error(), "network/CIDR") {
		t.Fatalf("network edit error=%v, want explicit rejection", err)
	}
	unchanged, err := bot.resolveTelegramTarget(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Domain != "example.org" || unchanged.Name != "web" || unchanged.Kind != "web" {
		t.Fatalf("rejected edit was not atomic: %+v", unchanged)
	}

	if _, err := bot.startTelegramScan(ctx, telegramTarget{Kind: "network"}, "deep"); err == nil || !strings.Contains(err.Error(), "network/CIDR") {
		t.Fatalf("legacy network scan error=%v, want explicit rejection", err)
	}
}

func TestTelegramViewerCannotMutateAndSkipPhaseAliasIsAudited(t *testing.T) {
	h, _ := newIsoHandler(t)
	bot := NewTelegramBot(h)
	var messages []map[string]any
	server := telegramAPIMock(t, &messages)
	defer server.Close()
	bot.apiBase = server.URL
	ctx := context.Background()

	bot.handleCommand(ctx, "token", TelegramChat{ChatID: "1001", Role: "viewer"}, "/addtarget example.org | denied")
	bot.handleCommand(ctx, "token", TelegramChat{ChatID: "1001", Role: "viewer"}, "/scan example.org")
	var targets, tasks int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&targets)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(&tasks)
	if targets != 0 || tasks != 0 {
		t.Fatalf("viewer mutation escaped RBAC: targets=%d tasks=%d", targets, tasks)
	}

	target, err := bot.createTelegramTarget(ctx, "example.org", "web")
	if err != nil {
		t.Fatal(err)
	}
	bot.handleCommand(ctx, "token", TelegramChat{ChatID: "2002", Role: "operator"}, "/skipphase "+target.ID)
	var action, status string
	if err := h.db.QueryRow(`SELECT action,status FROM telegram_audit_log WHERE chat_id='2002' ORDER BY created_at DESC LIMIT 1`).Scan(&action, &status); err != nil {
		t.Fatal(err)
	}
	if action != "scan_skip" || status != "failed" {
		t.Fatalf("skipphase alias audit=(%q,%q), want (scan_skip,failed)", action, status)
	}
}

func TestTelegramHelpIncludesSkipForOperatorsOnly(t *testing.T) {
	bot := &TelegramBot{}
	if strings.Contains(bot.helpText("viewer"), "/skip") {
		t.Fatal("viewer help exposed scan controls")
	}
	if !strings.Contains(bot.helpText("operator"), "/skip <target>") {
		t.Fatal("operator help is missing skip phase")
	}
	foundButton := false
	for _, row := range bot.scanKeyboard("target-id").Rows {
		for _, button := range row {
			if button.CallbackData == "skip:target-id" {
				foundButton = true
			}
		}
	}
	if !foundButton {
		t.Fatal("scan notification keyboard is missing skip phase")
	}
}

func TestTelegramFindingsListsOnlyValidatedResultsAcrossStores(t *testing.T) {
	h, _ := newIsoHandler(t)
	bot := NewTelegramBot(h)
	target, err := bot.createTelegramTarget(context.Background(), "example.org", "Example")
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO vuln_findings(id,target_id,type,severity,url,parameter,status,triage) VALUES('vf',?,'sqli','critical','https://example.org/a','id','finding','')`, []any{target.ID}},
		{`INSERT INTO vuln_findings(id,target_id,type,severity,url,parameter,status,triage) VALUES('fp',?,'false_noise','high','https://example.org/noise','','finding','false_positive')`, []any{target.ID}},
		{`INSERT INTO nuclei_findings(id,target_id,template_id,template_name,severity,matched_url,verification,verified_at) VALUES('nf',?,'cve','verified_cve','high','https://example.org/cve','verified',CURRENT_TIMESTAMP)`, []any{target.ID}},
		{`INSERT INTO open_redirect_findings(id,target_id,url,parameter,verified,status) VALUES('or',?,'https://example.org/redirect','next',1,'finding')`, []any{target.ID}},
		{`INSERT INTO backup_findings(id,target_id,url,file_type) VALUES('bf',?,'https://example.org/.env','env')`, []any{target.ID}},
		{`INSERT INTO js_files(id,target_id,url) VALUES('js',?,'https://example.org/app.js')`, []any{target.ID}},
		{`INSERT INTO js_findings(id,target_id,js_file_id,type,value,severity,verified) VALUES('jf',?,'js','secret_exposure','token','medium',1)`, []any{target.ID}},
	}
	for _, stmt := range statements {
		if _, err := h.db.Exec(stmt.query, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	text := bot.findingsText(context.Background(), target.ID)
	for _, expected := range []string{"sqli", "verified_cve", "open_redirect", "backup_exposure", "secret_exposure"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q from findings output:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "false_noise") {
		t.Fatalf("false-positive result leaked into verified findings:\n%s", text)
	}
	status := bot.statusText(context.Background())
	if !strings.Contains(status, "Verified findings: 5 (1 critical)") {
		t.Fatalf("cross-store finding totals are wrong: %s", status)
	}
}

func TestNotifyNewHostsDeduplicatesReplayByEventID(t *testing.T) {
	h, _ := newIsoHandler(t)
	bot := NewTelegramBot(h)
	if _, err := h.db.Exec(`INSERT INTO telegram_config(id,encrypted_bot_token,enabled) VALUES(1,'test-token',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := bot.AddChat(context.Background(), TelegramChat{ChatID: "1009", Label: "ops", Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	bot.NotifyNewHosts("newhost:deep-event-1", "2 new hosts", []string{"a.example.test", "b.example.test"}, "target-1")
	bot.NotifyNewHosts("newhost:deep-event-1", "2 new hosts", []string{"a.example.test", "b.example.test"}, "target-1")
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE event_key='newhost:deep-event-1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("outbox rows = %d, want one per enabled chat", n)
	}
}

func setupTelegramDeliveryTest(t *testing.T) (*Handler, *TelegramBot, *[]map[string]any, func()) {
	t.Helper()
	h, _ := newIsoHandler(t)
	h.cfg.SessionSecret = "unit-test-session-secret"
	bot := NewTelegramBot(h)
	bot.coalesceWindow = 0
	var messages []map[string]any
	server := telegramAPIMock(t, &messages)
	bot.apiBase = server.URL
	token := "123456789:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
	enabled := true
	if err := bot.Configure(context.Background(), &token, &enabled); err != nil {
		server.Close()
		t.Fatal(err)
	}
	if _, err := bot.AddChat(context.Background(), TelegramChat{ChatID: "1001", Label: "ops", Role: "operator"}); err != nil {
		server.Close()
		t.Fatal(err)
	}
	return h, bot, &messages, server.Close
}

func assertCompactAlertKeyboard(t *testing.T, msg map[string]any, targetID string) {
	t.Helper()
	markup, ok := msg["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("expected compact reply_markup, got %#v", msg["reply_markup"])
	}
	rows, ok := markup["inline_keyboard"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("expected 1-row alert keyboard, got %#v", markup["inline_keyboard"])
	}
	row, ok := rows[0].([]any)
	if !ok || len(row) != 1 {
		t.Fatalf("expected 1 button in alert keyboard, got %#v", rows[0])
	}
	btn, _ := row[0].(map[string]any)
	if btn["text"] != "Target" || btn["callback_data"] != "target:"+targetID {
		t.Fatalf("unexpected alert keyboard button: %#v", btn)
	}
}

func TestTelegramDisplayDomainCollapsesMultiURLTargets(t *testing.T) {
	h, _ := newIsoHandler(t)
	bot := NewTelegramBot(h)
	ctx := context.Background()

	if got := displayDomain("https://a.example.test/app, https://b.example.test/api, https://c.example.test/v2"); got != "a.example.test (+2 more)" {
		t.Fatalf("displayDomain multi-URL = %q, want %q", got, "a.example.test (+2 more)")
	}
	if got := displayDomain("https://single.example.test/path?q=1"); got != "single.example.test" {
		t.Fatalf("displayDomain single URL = %q, want %q", got, "single.example.test")
	}
	longDomain := strings.Repeat("a", 80) + ".example.test"
	if got := displayDomain(longDomain); len([]rune(got)) != 60 || !strings.HasSuffix(got, "…") {
		t.Fatalf("displayDomain cap = %q (runes=%d), want 60 runes ending with ellipsis", got, len([]rune(got)))
	}

	named, err := bot.createTelegramTarget(ctx, "https://a.example.test,https://b.example.test,https://c.example.test", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	if got := bot.targetLabel(ctx, named.ID, named.Domain); got != "Acme Corp" {
		t.Fatalf("targetLabel named = %q, want %q", got, "Acme Corp")
	}

	unnamed, err := bot.createTelegramTarget(ctx, "https://x.example.test,https://y.example.test,https://z.example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := bot.targetLabel(ctx, unnamed.ID, unnamed.Domain); got != "x.example.test (+2 more)" {
		t.Fatalf("targetLabel unnamed multi-URL = %q, want %q", got, "x.example.test (+2 more)")
	}
}

func TestTelegramHTTPStatusBurstCoalescesWithCompactArrowFormat(t *testing.T) {
	h, bot, messages, cleanup := setupTelegramDeliveryTest(t)
	defer cleanup()
	ctx := context.Background()

	target, err := bot.createTelegramTarget(ctx, "https://api.acme.test,https://app.acme.test", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	flips := []struct {
		id, url, oldVal, newVal string
	}{
		{"ev-1", "https://api.acme.test/admin", "403", "200"},
		{"ev-2", "https://stage.acme.test/", "HTTP 502", "HTTP 200"},
		{"ev-3", "https://old.acme.test/login", "status=200 title=Login", "status=404 title=Not Found"},
		{"ev-4", "https://cdn.acme.test/v2", "HTTP 301", "HTTP 200"},
		{"ev-5", "https://auth.acme.test/sso", "500", "200"},
	}
	for _, f := range flips {
		bot.NotifyHTTPStatus(target.ID, target.Domain, "status_change", "HTTP response changed", f.url, f.oldVal, f.newVal, f.id)
	}
	bot.drainOutbox(ctx)

	if len(*messages) != 1 {
		t.Fatalf("expected 1 coalesced HTTP status message, got %d", len(*messages))
	}
	text, _ := (*messages)[0]["text"].(string)
	for _, want := range []string{
		"HTTP status · Acme Corp (5)",
		"• https://api.acme.test/admin  403 → 200",
		"• https://stage.acme.test/  502 → 200",
		"• https://old.acme.test/login  200 → 404",
		"• https://cdn.acme.test/v2  301 → 200",
		"• https://auth.acme.test/sso  500 → 200",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in coalesced message:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"Old:", "New:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unexpected boilerplate %q in message:\n%s", forbidden, text)
		}
	}
	assertCompactAlertKeyboard(t, (*messages)[0], target.ID)

	var sent, pending int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE status='sent'`).Scan(&sent); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE status='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if sent != 5 || pending != 0 {
		t.Fatalf("expected 5 sent / 0 pending, got sent=%d pending=%d", sent, pending)
	}
}

func TestTelegramProgramScopeBurstCoalescesWithProgramName(t *testing.T) {
	h, bot, messages, cleanup := setupTelegramDeliveryTest(t)
	defer cleanup()
	ctx := context.Background()

	target, err := bot.createTelegramTarget(ctx, "acme.test", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	progID := "11111111-2222-3333-4444-555555555555"
	if _, err := h.db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name) VALUES(?,?,?,?,?)`,
		progID, "hackerone", "ext-acme", "acme-bb", "Acme Bug Bounty"); err != nil {
		t.Fatal(err)
	}
	events := []struct {
		id, typ, asset string
	}{
		{"sc-1", "added", "api.acme.test"},
		{"sc-2", "modified", "app.acme.test"},
		{"sc-3", "removed", "legacy.acme.test"},
		{"sc-4", "rule_added", "staging.acme.test"},
	}
	for _, ev := range events {
		bot.NotifyProgramScope(target.ID, target.Domain, progID, ev.typ, ev.asset, ev.id)
	}
	bot.drainOutbox(ctx)

	if len(*messages) != 1 {
		t.Fatalf("expected 1 coalesced scope message, got %d", len(*messages))
	}
	text, _ := (*messages)[0]["text"].(string)
	for _, want := range []string{
		"Scope · Acme Corp (Acme Bug Bounty) (4)",
		"+ api.acme.test (pending)",
		"~ app.acme.test (modified)",
		"- legacy.acme.test (removed)",
		"⊘ staging.acme.test (deny rule added)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in scope message:\n%s", want, text)
		}
	}
	if strings.Contains(text, progID) {
		t.Fatalf("raw program UUID leaked into scope message:\n%s", text)
	}
	assertCompactAlertKeyboard(t, (*messages)[0], target.ID)
}

func TestTelegramFindingsBurstCoalescesIntoOneMessage(t *testing.T) {
	_, bot, messages, cleanup := setupTelegramDeliveryTest(t)
	defer cleanup()
	ctx := context.Background()

	target, err := bot.createTelegramTarget(ctx, "acme.test", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	bot.NotifyNewVuln("f-1", target.ID, target.Domain, "sqli", "high", "https://api.acme.test/users", "id")
	bot.NotifyNewVuln("f-2", target.ID, target.Domain, "open_redirect", "medium", "https://app.acme.test/login", "next")
	bot.NotifyNewVuln("f-3", target.ID, target.Domain, "xss", "critical", "https://app.acme.test/search", "")
	bot.drainOutbox(ctx)

	if len(*messages) != 1 {
		t.Fatalf("expected 1 coalesced findings message, got %d", len(*messages))
	}
	text, _ := (*messages)[0]["text"].(string)
	for _, want := range []string{
		"Verified findings · Acme Corp (3)",
		"• [HIGH] sqli — https://api.acme.test/users (param: id)",
		"• [MEDIUM] open_redirect — https://app.acme.test/login (param: next)",
		"• [CRITICAL] xss — https://app.acme.test/search",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in findings message:\n%s", want, text)
		}
	}
	if strings.Contains(text, "(param: )") {
		t.Fatalf("empty param rendered in findings message:\n%s", text)
	}
}

func TestTelegramMonitorChangeDropsHashOnlyJSAndFormatsSecurityCompactly(t *testing.T) {
	h, bot, messages, cleanup := setupTelegramDeliveryTest(t)
	defer cleanup()
	ctx := context.Background()

	target, err := bot.createTelegramTarget(ctx, "acme.test", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	bot.NotifyMonitorChange(target.ID, target.Domain, "js_change", "JavaScript changed", "https://app.acme.test/bundle.js", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "m-js")
	bot.NotifyMonitorChange(target.ID, target.Domain, "css_change", "Stylesheet content changed", "https://app.acme.test/app.css", "cccccccccccccccccccccccccccccccc", "dddddddddddddddddddddddddddddddd", "m-css")
	bot.NotifyMonitorChange(target.ID, target.Domain, "security:stylesheet_added", "External stylesheet added", "https://app.acme.test/", "", "added stylesheet: https://cdn.acme.test/s.css", "m-ss")

	var noisyRows int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox`).Scan(&noisyRows); err != nil {
		t.Fatal(err)
	}
	if noisyRows != 0 {
		t.Fatalf("hash-only JS/CSS changes produced %d outbox rows, want 0", noisyRows)
	}

	bot.NotifyMonitorChange(target.ID, target.Domain, "security_header_removed", "Security header removed", "https://app.acme.test/", "Content-Security-Policy present", "Content-Security-Policy removed", "m-hdr")
	bot.NotifyMonitorChange(target.ID, target.Domain, "security:script_added", "Change detected", "https://app.acme.test/", "", "added script: https://cdn.evil.test/a.js", "m-scr")
	bot.drainOutbox(ctx)

	if len(*messages) != 1 {
		t.Fatalf("expected 1 coalesced monitoring message, got %d", len(*messages))
	}
	text, _ := (*messages)[0]["text"].(string)
	for _, want := range []string{
		"Security drift · Acme Corp (2)",
		"• https://app.acme.test/ — Content-Security-Policy header removed",
		"• https://app.acme.test/ — External script added: https://cdn.evil.test/a.js",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in monitoring message:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"Old:", "New:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unexpected boilerplate %q in monitoring message:\n%s", forbidden, text)
		}
	}
	assertCompactAlertKeyboard(t, (*messages)[0], target.ID)
}

func TestTelegramLargeBurstCapsListCleanly(t *testing.T) {
	h, bot, messages, cleanup := setupTelegramDeliveryTest(t)
	defer cleanup()
	ctx := context.Background()

	target, err := bot.createTelegramTarget(ctx, "acme.test", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 25; i++ {
		u := fmt.Sprintf("https://host-%02d.acme.test/", i)
		bot.NotifyHTTPStatus(target.ID, target.Domain, "status_change", "HTTP response changed", u, "403", "200", fmt.Sprintf("burst-%02d", i))
	}
	bot.drainOutbox(ctx)

	if len(*messages) != 1 {
		t.Fatalf("expected 1 capped message for 25 short status flips, got %d", len(*messages))
	}
	text, _ := (*messages)[0]["text"].(string)
	if !strings.Contains(text, "HTTP status · Acme Corp (25)") {
		t.Fatalf("missing burst header:\n%s", text)
	}
	if got := strings.Count(text, "• https://"); got != 20 {
		t.Fatalf("listed %d items, want 20:\n%s", got, text)
	}
	if !strings.Contains(text, "… +5 more in Changes") {
		t.Fatalf("missing truncation footer:\n%s", text)
	}
	var sent, pending int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE status='sent'`).Scan(&sent); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE status='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if sent != 25 || pending != 0 {
		t.Fatalf("expected 25 sent / 0 pending, got sent=%d pending=%d", sent, pending)
	}
}

func TestTelegramEdgeCasesSecurityAttributesStatusAndRetryIsolation(t *testing.T) {
	if got := extractHTTPStatusCode("status=0 title=Error 500"); got != 0 {
		t.Fatalf("extractHTTPStatusCode parsed title number %d on status=0, want 0", got)
	}
	longMulti := displayDomain("very-long-application-gateway-subdomain.internal.example.com, other.example.com")
	if !strings.HasSuffix(longMulti, " (+1 more)") || len([]rune(longMulti)) > 60 {
		t.Fatalf("displayDomain chopped count suffix or exceeded 60 runes: %q", longMulti)
	}

	h, bot, messages, cleanup := setupTelegramDeliveryTest(t)
	defer cleanup()
	ctx := context.Background()

	if got := bot.targetLabel(ctx, "missing-id", "Acme Bug Bounty"); got != "Acme Bug Bounty" {
		t.Fatalf("targetLabel mangled space-separated fallback name: %q", got)
	}

	target, err := bot.createTelegramTarget(ctx, "acme.test", "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}

	// Two distinct security attribute alerts on the same URL must both render cleanly.
	bot.NotifyMonitorChange(target.ID, target.Domain, "security:iframe_added", "Change detected",
		"https://app.acme.test/login", "", "added iframe: https://evil.test/frame", "sec-iframe-1")
	bot.NotifyMonitorChange(target.ID, target.Domain, "security:form_added", "Change detected",
		"https://app.acme.test/login", "", "added form: https://evil.test/steal", "sec-form-1")
	bot.drainOutbox(ctx)

	if len(*messages) != 1 {
		t.Fatalf("expected 1 coalesced security message, got %d", len(*messages))
	}
	secText, _ := (*messages)[0]["text"].(string)
	if !strings.Contains(secText, "Iframe added: https://evil.test/frame") ||
		!strings.Contains(secText, "Form added: https://evil.test/steal") {
		t.Fatalf("distinct security alerts were collapsed or lost detail:\n%s", secText)
	}

	// Overflowed findings must point to Findings, not Changes.
	*messages = nil
	for i := 1; i <= 22; i++ {
		bot.NotifyNewVuln(fmt.Sprintf("vf-%02d", i), target.ID, target.Domain, "xss", "high",
			fmt.Sprintf("https://app.acme.test/p/%02d", i), "q")
	}
	bot.drainOutbox(ctx)
	if len(*messages) != 1 {
		t.Fatalf("expected 1 capped findings message, got %d", len(*messages))
	}
	findText, _ := (*messages)[0]["text"].(string)
	if !strings.Contains(findText, "… +2 more in Findings") {
		t.Fatalf("expected Findings overflow footer, got:\n%s", findText)
	}

	// An older row in retry backoff (attempts=7) must NOT poison-pill a fresh row (attempts=0).
	var chatEntryID string
	if err := h.db.QueryRow(`SELECT id FROM telegram_chats LIMIT 1`).Scan(&chatEntryID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO telegram_outbox(id,chat_entry_id,event_key,category,message,batch_key,target_id,item_json,status,attempts,next_attempt_at)
		VALUES('old-fail',?,'ev-old','http_status','old',?,?,'{"url":"https://old.acme.test/","old_code":403,"new_code":200}','pending',7,datetime('now','+120 seconds'))`,
		chatEntryID, "http_status:"+target.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	bot.NotifyHTTPStatus(target.ID, target.Domain, "status_change", "HTTP response changed",
		"https://fresh.acme.test/", "403", "200", "ev-fresh")
	bot.apiBase = "http://127.0.0.1:1" // force transient send error
	bot.drainOutbox(ctx)

	var freshStatus string
	var freshAttempts int
	if err := h.db.QueryRow(`SELECT status, attempts FROM telegram_outbox WHERE event_key='http-status:ev-fresh'`).Scan(&freshStatus, &freshAttempts); err != nil {
		t.Fatal(err)
	}
	if freshStatus != "pending" || freshAttempts != 1 {
		t.Fatalf("fresh alert was poison-billed: status=%q attempts=%d, want pending/1", freshStatus, freshAttempts)
	}
	var oldAttempts int
	if err := h.db.QueryRow(`SELECT attempts FROM telegram_outbox WHERE id='old-fail'`).Scan(&oldAttempts); err != nil {
		t.Fatal(err)
	}
	if oldAttempts != 7 {
		t.Fatalf("backoff row was retried early: attempts=%d, want 7", oldAttempts)
	}
}
