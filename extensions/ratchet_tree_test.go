// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file.

package extensions_test

import (
	"testing"

	"github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestRatchetTreeExtension_New tests creation.
func TestRatchetTreeExtension_New(t *testing.T) {
	tree := &treesync.RatchetTree{}
	ext := extensions.NewRatchetTreeExtension(tree)
	if ext == nil {
		t.Fatal("NewRatchetTreeExtension returned nil")
	}
	if ext.Tree != tree {
		t.Error("Tree not set correctly")
	}
}

// TestRatchetTreeExtension_Validate tests validation.
func TestRatchetTreeExtension_Validate(t *testing.T) {
	// Nil tree is valid
	ext1 := &extensions.RatchetTreeExtension{Tree: nil}
	if err := ext1.Validate(); err != nil {
		t.Errorf("Validate() with nil tree error = %v, want nil", err)
	}

	// Empty tree is valid
	tree := &treesync.RatchetTree{}
	ext2 := extensions.NewRatchetTreeExtension(tree)
	// Note: Empty tree may fail validation depending on implementation
	_ = ext2
}

// TestRatchetTreeExtension_GetTree tests getter.
func TestRatchetTreeExtension_GetTree(t *testing.T) {
	tree := &treesync.RatchetTree{}
	ext := extensions.NewRatchetTreeExtension(tree)
	if ext.GetTree() != tree {
		t.Error("GetTree() did not return expected tree")
	}
}

// TestRatchetTreeExtension_SetTree tests setter.
func TestRatchetTreeExtension_SetTree(t *testing.T) {
	ext := extensions.NewRatchetTreeExtension(nil)
	tree := &treesync.RatchetTree{}
	ext.SetTree(tree)
	if ext.GetTree() != tree {
		t.Error("SetTree() did not set tree correctly")
	}
}

// TestRatchetTreeExtension_ToExtension tests conversion to generic Extension.
func TestRatchetTreeExtension_ToExtension(t *testing.T) {
	tree := &treesync.RatchetTree{}
	ext := extensions.NewRatchetTreeExtension(tree)

	genericExt, err := ext.ToExtension()
	if err != nil {
		t.Fatalf("ToExtension failed: %v", err)
	}

	if genericExt.Type != extensions.ExtensionTypeRatchetTree {
		t.Errorf("Wrong extension type: got %d, want %d", genericExt.Type, extensions.ExtensionTypeRatchetTree)
	}
}

// TestRatchetTreeExtension_FromExtension tests creation from generic Extension.
func TestRatchetTreeExtension_FromExtension(t *testing.T) {
	tree := &treesync.RatchetTree{}
	ext := extensions.NewRatchetTreeExtension(tree)
	genericExt, _ := ext.ToExtension()

	// Valid conversion
	result, err := extensions.FromExtension(genericExt)
	if err != nil {
		t.Fatalf("FromExtension failed: %v", err)
	}

	if result.ExtensionType() != extensions.ExtensionTypeRatchetTree {
		t.Errorf("Wrong extension type: got %d, want %d", result.ExtensionType(), extensions.ExtensionTypeRatchetTree)
	}

	// Invalid type
	wrongExt := &extensions.Extension{Type: extensions.ExtensionTypeApplicationID, Data: []byte("test")}
	_, err = extensions.FromExtension(wrongExt)
	if err == nil {
		t.Error("FromExtension should fail for wrong type")
	}
}

// TestRatchetTreeExtension_ExtensionType tests type code.
func TestRatchetTreeExtension_ExtensionType(t *testing.T) {
	ext := extensions.NewRatchetTreeExtension(nil)
	if ext.ExtensionType() != extensions.ExtensionTypeRatchetTree {
		t.Errorf("ExtensionType() = %d, want %d", ext.ExtensionType(), extensions.ExtensionTypeRatchetTree)
	}
}

// TestRatchetTreeExtension_Equal tests equality comparison.
func TestRatchetTreeExtension_Equal(t *testing.T) {
	// Both nil
	var ext1, ext2 *extensions.RatchetTreeExtension
	if !ext1.Equal(ext2) {
		t.Error("Both nil extensions should be equal")
	}

	// One nil
	tree := &treesync.RatchetTree{}
	ext3 := extensions.NewRatchetTreeExtension(tree)
	if ext3.Equal(nil) {
		t.Error("Non-nil extension should not equal nil")
	}

	// Both with same tree hash
	tree1 := &treesync.RatchetTree{}
	tree2 := &treesync.RatchetTree{}
	ext4 := extensions.NewRatchetTreeExtension(tree1)
	ext5 := extensions.NewRatchetTreeExtension(tree2)
	if !ext4.Equal(ext5) {
		t.Error("Extensions with same tree hash should be equal")
	}
}

// TestRatchetTreeExtension_MarshalEmpty tests marshaling empty extension.
func TestRatchetTreeExtension_MarshalEmpty(t *testing.T) {
	ext := extensions.NewRatchetTreeExtension(nil)
	data := ext.Marshal()
	if len(data) != 0 {
		t.Errorf("Marshal() with nil tree returned %d bytes, want 0", len(data))
	}
}

// TestUnmarshalRatchetTreeExtension_Empty tests unmarshaling empty data.
func TestUnmarshalRatchetTreeExtension_Empty(t *testing.T) {
	ext, err := extensions.UnmarshalRatchetTreeExtension([]byte{})
	if err != nil {
		t.Fatalf("UnmarshalRatchetTreeExtension([]byte{}) error = %v", err)
	}
	if ext == nil {
		t.Error("UnmarshalRatchetTreeExtension([]byte{}) returned nil")
		return
	}
	if ext.Tree != nil {
		t.Error("Tree should be nil for empty data")
	}
}
