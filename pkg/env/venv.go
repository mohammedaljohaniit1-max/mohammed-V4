package env

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// VenvManager encapsulates management of an isolated Python virtual environment
// located in ~/.mohammed/venv to prevent PEP 668 and system package manager conflicts.
type VenvManager struct {
	VenvPath string
	BinPath  string
	Python   string
	Pip      string
}

// NewVenvManager initializes a VenvManager pointing to ~/.mohammed/venv.
func NewVenvManager() *VenvManager {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/home/user"
	}
	vPath := filepath.Join(home, ".mohammed", "venv")
	bPath := filepath.Join(vPath, "bin")
	return &VenvManager{
		VenvPath: vPath,
		BinPath:  bPath,
		Python:   filepath.Join(bPath, "python"),
		Pip:      filepath.Join(bPath, "pip"),
	}
}

// EnsureVenv bootstraps the virtual environment if it does not already exist.
func (v *VenvManager) EnsureVenv() error {
	if _, err := os.Stat(v.Python); err == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(v.VenvPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for venv: %w", err)
	}

	// Try creating virtual environment with python3 -m venv
	cmd := exec.Command("python3", "-m", "venv", v.VenvPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Fallback to virtualenv if venv module is missing
		cmd2 := exec.Command("virtualenv", v.VenvPath)
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("failed to create venv (venv: %v - %s, virtualenv: %v - %s)", err, string(out), err2, string(out2))
		}
	}

	return nil
}

// InstallPackage installs or upgrades a Python package inside the sandboxed venv.
func (v *VenvManager) InstallPackage(pkg string) error {
	if err := v.EnsureVenv(); err != nil {
		return err
	}

	cmd := exec.Command(v.Pip, "install", "--upgrade", pkg)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pip install %s failed: %w - %s", pkg, err, string(out))
	}
	return nil
}

// LookPath looks for an executable first in the isolated venv bin directory.
func (v *VenvManager) LookPath(name string) (string, error) {
	venvBin := filepath.Join(v.BinPath, name)
	if info, err := os.Stat(venvBin); err == nil && !info.IsDir() {
		return venvBin, nil
	}
	return exec.LookPath(name)
}

// EnforceVenvPath adds the venv bin directory to the front of PATH in the environment.
func (v *VenvManager) EnforceVenvPath() {
	currPath := os.Getenv("PATH")
	if !strings.Contains(currPath, v.BinPath) {
		_ = os.Setenv("PATH", v.BinPath+":"+currPath)
	}
}
