package env

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVenvManager_Bootstrap(t *testing.T) {
	vm := NewVenvManager()
	if vm.VenvPath == "" || vm.BinPath == "" || vm.Python == "" {
		t.Fatalf("expected non-empty paths in VenvManager: %+v", vm)
	}

	vm.EnforceVenvPath()
	currPath := os.Getenv("PATH")
	if !filepath.IsAbs(vm.BinPath) {
		t.Errorf("BinPath should be absolute: %s", vm.BinPath)
	}
	_ = currPath
}
