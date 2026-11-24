package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeURLWithContextRejectsOutOfScopeRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/landing", http.StatusFound)
	}))
	defer start.Close()

	ctx := WithHostScope(context.Background(), []string{"127.0.0.1"})
	if svc := probeURLWithContext(ctx, start.URL+"/start"); svc == nil || svc.StatusCode != http.StatusOK {
		t.Fatalf("same-host redirect was blocked: %+v", svc)
	}

	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://outside.invalid/secret", http.StatusFound)
	}))
	defer outside.Close()
	if svc := probeURLWithContext(ctx, outside.URL+"/start"); svc != nil {
		t.Fatalf("out-of-scope redirect was followed: %+v", svc)
	}
}
