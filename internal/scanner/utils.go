package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/recon-platform/internal/models"
)

type LogFunc func(level, module, message string)

func probeURL(url string) *models.HTTPService {
	return probeURLWithContext(context.Background(), url)
}

// probeURLWithContext runs the native fallback with the task context. It adds a
// scope check to every redirect so a request cannot follow an allowed URL to a
// destination outside the current project scope. The transport already blocks
// excluded CIDRs at connect time through scopeGuardedDialContext.
func probeURLWithContext(ctx context.Context, rawURL string) *models.HTTPService {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client := ScannerRedirectClient(10*time.Second, 5, RedirectInScope)

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}

	title := extractTitle(string(body))
	server := resp.Header.Get("Server")
	contentType := resp.Header.Get("Content-Type")

	return &models.HTTPService{
		URL:           rawURL,
		StatusCode:    resp.StatusCode,
		Title:         title,
		Server:        server,
		ContentType:   contentType,
		ContentLength: len(body),
	}
}

func extractTitle(body string) string {
	if !utf8.ValidString(body) {
		return ""
	}

	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}

	title := strings.TrimSpace(body[start : start+end])
	if len(title) > 255 {
		title = title[:255]
	}
	return title
}

// titleFirst upper-cases the first byte of an ASCII word (e.g. "mongodb" →
// "Mongodb"). Used for display labels of service names; replaces the deprecated
// strings.Title without pulling in golang.org/x/text for a one-letter change.
func titleFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 'a' - 'A'
	}
	return string(b)
}
