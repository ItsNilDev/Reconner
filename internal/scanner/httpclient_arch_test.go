package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAdHocScannerHTTPClients enforces the single HTTP choke-point rule:
// individual scanner modules must obtain clients through the shared factories
// in httpengine.go / destination.go (ScannerClient, ScannerRedirectClient,
// CredentialClient, DirectIPClient, ExternalClient) and must never construct
// ad-hoc http.Client / http.Transport instances or call http.DefaultClient /
// http.DefaultTransport / package-level http.Get/Post/Head directly.
func TestNoAdHocScannerHTTPClients(t *testing.T) {
	allowed := map[string]bool{
		"httpengine.go":       true,
		"destination.go":      true,
		"request_identity.go": true,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read scanner dir: %v", err)
	}

	fset := token.NewFileSet()
	var violations []string

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if allowed[name] {
			continue
		}

		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				if sel, ok := node.Type.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "http" {
						if sel.Sel.Name == "Client" || sel.Sel.Name == "Transport" {
							pos := fset.Position(node.Pos())
							violations = append(violations, pos.String()+": ad-hoc http."+sel.Sel.Name+" literal (use ScannerClient/ScannerRedirectClient/CredentialClient/DirectIPClient/ExternalClient)")
						}
					}
				}
			case *ast.SelectorExpr:
				if ident, ok := node.X.(*ast.Ident); ok && ident.Name == "http" {
					switch node.Sel.Name {
					case "DefaultClient", "DefaultTransport", "Get", "Post", "PostForm", "Head":
						pos := fset.Position(node.Pos())
						violations = append(violations, pos.String()+": forbidden http."+node.Sel.Name+" reference (use choke-point client with context)")
					}
				}
			}
			return true
		})
	}

	if len(violations) > 0 {
		t.Fatalf("HTTP choke-point architecture violations:\n  %s", strings.Join(violations, "\n  "))
	}
}
