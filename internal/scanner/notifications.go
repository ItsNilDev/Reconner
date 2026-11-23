package scanner

import (
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// statusCodeFromValue extracts the numeric HTTP code from a stored change
// value of the form "status=NNN title=...". It returns 0 when no code is
// present. Callers use the code to carry an exact old/new transition through
// the broadcast and into the Telegram alert.
func statusCodeFromValue(value string) int {
	const prefix = "status="
	if !strings.HasPrefix(value, prefix) {
		return 0
	}
	rest := value[len(prefix):]
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = rest[:i]
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 100 || n > 599 {
		return 0
	}
	return n
}

// notify persists an operator-facing notification (rendered in the bell menu).
// Best-effort: a failed insert never breaks the scan that raised it. Callers are
// responsible for only raising HIGH-SIGNAL events (a real, deduped change) so the
// bell stays free of false positives.
func notify(db *database.DB, targetID, typ, title, body, url, severity string) {
	notifyWithMetadata(db, targetID, typ, title, body, url, severity, "{}")
}

// notifyWithMetadata persists an operator-facing notification together with a
// JSON metadata blob. Callers that need to keep structured details (for example
// the list of new subdomain host names) use this variant; the bell body stays a
// short human-readable summary. Best-effort: a failed insert never breaks the
// scan that raised it.
func notifyWithMetadata(db *database.DB, targetID, typ, title, body, url, severity, metadata string) {
	notifyWithIdentity(db, targetID, typ, title, body, url, severity, metadata, "", "", "")
}

// notifyWithIdentity persists a notification together with the identity and
// structured values of the underlying change. The identity is the change id,
// so downstream alerts can point at one event without re-querying by type and
// time. The generated notification id is returned for callers that need it.
func notifyWithIdentity(db *database.DB, targetID, typ, title, body, url, severity, metadata, changeID, oldValue, newValue string) string {
	if severity == "" {
		severity = "info"
	}
	if metadata == "" {
		metadata = "{}"
	}
	id := uuid.New().String()
	_, _ = db.Exec(`
		INSERT INTO notifications (id, target_id, type, title, body, url, severity, is_read, metadata, change_id, old_value, new_value, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		id, targetID, typ, title, body, url, severity, metadata, changeID, oldValue, newValue)
	return id
}
