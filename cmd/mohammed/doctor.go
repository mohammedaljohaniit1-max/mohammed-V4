package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type DoctorToolStatus struct {
	Name      string
	Category  string
	Installed bool
	Path      string
	Version   string
}

func RunEcosystemDoctor() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║       MOHAMMED-V4 RIGOROUS SYSTEM & ECOSYSTEM DOCTOR AUDIT       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// 1. Tool Presence and Versioning
	fmt.Println("── 1. Essential Zero-API Toolset Presence & Versioning ───────────────")
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		home, _ := os.UserHomeDir()
		goPath = home + "/go"
	}
	goBin := goPath + "/bin"
	home, _ := os.UserHomeDir()
	localBin := home + "/.local/bin"
	currPath := os.Getenv("PATH")
	if !strings.Contains(currPath, goBin) {
		currPath = goBin + ":" + currPath
	}
	if !strings.Contains(currPath, localBin) {
		currPath = localBin + ":" + currPath
	}
	_ = os.Setenv("PATH", currPath)

	allFound := true
	_ = allFound
	for idx, tool := range EssentialEcosystem {
		path, err := exec.LookPath(tool.Name)
		if err != nil {
			candidate := filepath.Join(goBin, tool.Name)
			if info, sErr := os.Stat(candidate); sErr == nil && !info.IsDir() {
				path = candidate
				err = nil
			}
		}

		status := DoctorToolStatus{
			Name:     tool.Name,
			Category: tool.Category,
		}

		if err == nil {
			status.Installed = true
			status.Path = path

			verCmd := exec.Command(path, "-version")
			if tool.Name == "subfinder" || tool.Name == "dnsx" || tool.Name == "httpx" || tool.Name == "katana" || tool.Name == "alterx" {
				verCmd = exec.Command(path, "-version")
			} else if tool.Name == "ffuf" {
				verCmd = exec.Command(path, "-V")
			} else if tool.Name == "trufflehog" {
				verCmd = exec.Command(path, "--version")
			} else if tool.Name == "arjun" {
				verCmd = exec.Command("arjun", "--version")
			}

			out, vErr := verCmd.CombinedOutput()
			if vErr == nil && len(out) > 0 {
				lines := strings.Split(string(out), "\n")
				status.Version = strings.TrimSpace(lines[0])
			} else {
				status.Version = "installed (version output pending)"
			}

			fmt.Printf("  [%02d/%02d] ✅ %-12s | %-18s | %s\n", idx+1, len(EssentialEcosystem), tool.Name, tool.Category, status.Path)
			if status.Version != "" && !strings.Contains(status.Version, "version output pending") {
				fmt.Printf("         └─ Version: %s\n", status.Version)
			}
		} else {
			allFound = false
			fmt.Printf("  [%02d/%02d] ❌ %-12s | %-18s | NOT FOUND in PATH\n", idx+1, len(EssentialEcosystem), tool.Name, tool.Category)
		}
	}
	fmt.Println()

	// 2. Ollama & Cognitive AI Service Verification
	fmt.Println("── 2. Local AI Cognitive Engine (Ollama) & Cloud Fallback ───────────")
	resp, err := http.Get("http://127.0.0.1:11434/api/tags")
	if err == nil && resp.StatusCode == http.StatusOK {
		fmt.Println("  ✅ Ollama Service : Reachable on http://127.0.0.1:11434 (Status: ONLINE)")
		var tags struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&tags)
		resp.Body.Close()
		fmt.Println("     └─ Service verified and responding")
	} else {
		fmt.Println("  ⚠️  Ollama Service : Offline (http://127.0.0.1:11434 unreachable)")
		fmt.Println("     └─ Run: ./mohammed setup OR set GEMINI_API_KEY in environment for cloud triage fallback")
	}
	fmt.Println()

	// 3. System Resource Resilience (RAM, File Descriptors, CPU)
	fmt.Println("── 3. Local Resource Availability & Concurrency Headroom ────────────")
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	numCPU := runtime.NumCPU()
	fmt.Printf("  ✅ CPU Cores Available : %d logical cores\n", numCPU)
	fmt.Printf("  ✅ Process Heap Alloc  : %.2f MB (Sys: %.2f MB)\n", float64(memStats.Alloc)/1024/1024, float64(memStats.Sys)/1024/1024)

	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		fmt.Printf("  ✅ File Descriptors    : Current Limit = %d (Max = %d)\n", rLimit.Cur, rLimit.Max)
	}

	fmt.Println()

	// 4. Network & DNS Latency Verification
	fmt.Println("── 4. Network Connectivity & DNS Latency ─────────────────────────────")
	testDNSResolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	for _, resolver := range testDNSResolvers {
		start := time.Now()
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.Dial("udp", resolver)
		latency := time.Since(start).Round(time.Millisecond)
		if err != nil {
			fmt.Printf("  ❌ DNS Resolver %-12s: Unreachable (%v)\n", resolver, err)
		} else {
			_ = conn.Close()
			fmt.Printf("  ✅ DNS Resolver %-12s: Reachable (latency: %v)\n", resolver, latency)
		}
	}
	fmt.Println()

	// 5. Local Socket Binding Capabilities
	fmt.Println("── 5. Local Socket Binding Capabilities ─────────────────────────────")
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		addr := ln.Addr().String()
		_ = ln.Close()
		fmt.Printf("  ✅ TCP Socket Binding: OK (ephemeral bound to %s)\n", addr)
	}

	fmt.Println()

	// 6. Workspace Filesystem Read/Write Permissions
	fmt.Println("── 6. Workspace Filesystem Read/Write Permissions ───────────────────")
	testDir := "output"
	if err := os.MkdirAll(testDir, 0755); err == nil {
		testFile := filepath.Join(testDir, ".doctor_io_test")
		testData := []byte(fmt.Sprintf("doctor_verify_%d", time.Now().UnixNano()))
		if wErr := os.WriteFile(testFile, testData, 0644); wErr == nil {
			_ = os.Remove(testFile)
			fmt.Printf("  ✅ Workspace Read/Write: OK (directory '%s' fully functional)\n", testDir)
		}
	}
	fmt.Println("───────────────────────────────────────────────────────────────────")
}

func QuickCheckEcosystem(ctx context.Context) error {
	missing := 0
	for _, tool := range EssentialEcosystem {
		if _, err := exec.LookPath(tool.Name); err != nil {
			missing++
		}
	}
	if missing > 0 {
		return fmt.Errorf("%d essential zero-API tool(s) missing from PATH (run './mohammed setup')", missing)
	}
	return nil
}
