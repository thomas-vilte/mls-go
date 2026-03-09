package group

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type passiveClientVector struct {
	Name string `json:"name"`
}

func TestPassiveClientVectors(t *testing.T) {
	matches, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}

	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		var v passiveClientVector
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("unmarshal %s: %v", path, err)
		}

		t.Run(v.Name, func(t *testing.T) {
			// TODO: execute passive client interop vectors.
		})
	}
}
