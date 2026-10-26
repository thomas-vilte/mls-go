//go:build diagnostics

package mls

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCICoversNestedModules checks that every nested Go module is listed
// in the CI matrix and that the workflow includes vet and race-enabled tests.
func TestCICoversNestedModules(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("reading ci.yml: %v", err)
	}
	ci := string(raw)
	if !strings.Contains(ci, "nested:") {
		t.Fatalf("ci.yml has no nested job")
	}
	var modules []string
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" && path != "." {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == "go.mod" {
			dir := filepath.ToSlash(filepath.Dir(path))
			if dir != "." {
				modules = append(modules, dir)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking tree: %v", err)
	}
	if len(modules) == 0 {
		t.Fatalf("no nested go.mod found; the test is not checking anything")
	}
	matrixLine := ""
	for _, line := range strings.Split(ci, "\n") {
		if strings.Contains(line, "module: [") {
			matrixLine = line
		}
	}
	if matrixLine == "" {
		t.Fatalf("ci.yml has no 'module: [...]' matrix line")
	}
	for _, m := range modules {
		if !strings.Contains(matrixLine, m) {
			t.Errorf("nested module %q is not in the nested CI matrix line %q", m, strings.TrimSpace(matrixLine))
		}
	}
	// Each nested module must run vet and uncached tests with the race detector.
	for _, step := range []string{"go vet ./...", "go test -race -count=1 ./..."} {
		if !strings.Contains(ci, step) {
			t.Errorf("ci.yml does not run %q for the nested modules", step)
		}
	}
}
