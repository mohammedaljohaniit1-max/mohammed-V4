package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"net/http"
	"strings"
	"time"
)

// ZeroAPIEcosystem represents the 10 essential tools for passive & active reconnaissance,
// content/parameter discovery, and secret scanning without requiring paid commercial APIs.
type ToolSpec struct {
	Name         string
	Category     string
	Description  string
	GoPackage    string
	InstallCmd   string   // Primary custom shell installation command
	AptPackage   string   // Debian/Ubuntu fallback
	BinaryURLs   map[string]string // OS/Arch -> Pre-compiled release asset fallback
}

var EssentialEcosystem = []ToolSpec{
	// 1. Recon & Probing
	{
		Name:        "subfinder",
		Category:    "Recon & Discovery",
		Description: "Fast passive subdomain enumeration via public OSINT sources",
		GoPackage:   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		AptPackage:  "subfinder",
	},
	{
		Name:        "dnsx",
		Category:    "Recon & DNS",
		Description: "Multi-purpose DNS toolkit for wildcard filtering and bulk resolution",
		GoPackage:   "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
	},
	{
		Name:        "httpx",
		Category:    "Probing & Discovery",
		Description: "High-performance HTTP probe validating alive targets, titles, and tech stacks",
		GoPackage:   "github.com/projectdiscovery/httpx/cmd/httpx@latest",
		AptPackage:  "httpx-toolkit",
	},
	{
		Name:        "katana",
		Category:    "Crawling & Scraping",
		Description: "Next-generation web crawler for endpoint and parameter discovery",
		GoPackage:   "github.com/projectdiscovery/katana/cmd/katana@latest",
	},
	{
		Name:        "gau",
		Category:    "Archive Harvesting",
		Description: "Fetches known URLs from Wayback, AlienVault OTX, and Common Crawl",
		GoPackage:   "github.com/lc/gau/v2/cmd/gau@latest",
	},
	{
		Name:        "alterx",
		Category:    "Permutation & Mutation",
		Description: "Fast, pattern-based subdomain wordlist generator",
		GoPackage:   "github.com/projectdiscovery/alterx/cmd/alterx@latest",
	},

	// 2. Content & Parameter Discovery
	{
		Name:        "arjun",
		Category:    "Parameter Discovery",
		Description: "HTTP parameter discovery suite (GET/POST/JSON query reflection)",
		InstallCmd:  "pip3 install --upgrade arjun || pip install --upgrade arjun",
		AptPackage:  "arjun",
	},
	{
		Name:        "ffuf",
		Category:    "Fuzzing & Content",
		Description: "Fast web fuzzer written in Go for paths, virtual hosts, and parameters",
		GoPackage:   "github.com/ffuf/ffuf/v2@latest",
		AptPackage:  "ffuf",
	},
	{
		Name:        "cariddi",
		Category:    "Asset Extraction",
		Description: "Extracts endpoints, secrets, and query parameters from HTTP responses",
		GoPackage:   "github.com/edoardottt/cariddi/cmd/cariddi@latest",
	},

	// 3. Secret & Signature Verification
	{
		Name:        "trufflehog",
		Category:    "Secret Verification",
		Description: "High-accuracy credentials and API secret detector with live verification",
		GoPackage:   "github.com/trufflesecurity/trufflehog/v3@latest",
		InstallCmd:  "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
	},
}

// RunEcosystemSetup executes the automated installation with 3-tier fallbacks:
// Tier 1: Direct Go compilation (go install) / dedicated script
// Tier 2: System package manager (apt/brew)
// Tier 3: Binary release fallback
func RunEcosystemSetup() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║     MOHAMMED-V4 ZERO-API HYBRID ECOSYSTEM SETUP & INSTALLER       ║")
	fmt.Println("║             (Multi-Tier Compilation & Package Fallback)           ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Ensure $GOPATH/bin and ~/.local/bin are in PATH for current process
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

	fmt.Printf("[*] Target Binary Search Path: %s\n", currPath)
	fmt.Printf("[*] Platform Architecture: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	success := 0
	failed := 0

	for idx, tool := range EssentialEcosystem {
		fmt.Printf("[%d/%d] Resolving & Installing %-12s (%s)...\n", idx+1, len(EssentialEcosystem), tool.Name, tool.Category)

		// Check if already installed
		if p, err := exec.LookPath(tool.Name); err == nil {
			fmt.Printf("   ✔ Already present in PATH: %s\n", p)
			success++
			continue
		}

		installed := false

		// Tier 1: Go install or primary install command
		if tool.GoPackage != "" {
			cmd := exec.Command("go", "install", "-v", tool.GoPackage)
			cmd.Env = os.Environ()
			if out, err := cmd.CombinedOutput(); err == nil {
				fmt.Printf("   ✅ Successfully installed via 'go install': %s\n", tool.Name)
				installed = true
			} else {
				fmt.Printf("   ⚠️  'go install' failed: %v (trying fallback)\n", err)
				_ = out
			}
		} else if tool.InstallCmd != "" {
			cmd := exec.Command("bash", "-c", tool.InstallCmd)
			cmd.Env = os.Environ()
			if out, err := cmd.CombinedOutput(); err == nil {
				fmt.Printf("   ✅ Successfully installed via script: %s\n", tool.Name)
				installed = true
			} else {
				fmt.Printf("   ⚠️  Primary script failed: %v (trying fallback)\n", err)
				_ = out
			}
		}

		// Tier 2: Apt package manager fallback (Debian/Ubuntu/Kali)
		if !installed && tool.AptPackage != "" && runtime.GOOS == "linux" {
			if _, err := exec.LookPath("apt-get"); err == nil {
				fmt.Printf("   [*] Attempting apt-get install: %s\n", tool.AptPackage)
				cmd := exec.Command("sudo", "apt-get", "install", "-y", tool.AptPackage)
				if err := cmd.Run(); err == nil {
					fmt.Printf("   ✅ Successfully installed via apt-get: %s\n", tool.Name)
					installed = true
				}
			}
		}

		// Tier 3: Secondary custom fallback for specific tools
		if !installed && tool.Name == "trufflehog" && tool.InstallCmd != "" {
			cmd := exec.Command("bash", "-c", tool.InstallCmd)
			if err := cmd.Run(); err == nil {
				fmt.Printf("   ✅ Successfully installed trufflehog via release script\n")
				installed = true
			}
		}

		if installed {
			success++
		} else {
			fmt.Printf("   ❌ Could not install %s automatically. Please install manually.\n", tool.Name)
			failed++
		}
	}

	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Printf("[+] Setup Complete: %d ready/installed, %d unresolved\n", success, failed)
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println("[*] Launching system health doctor check...")
	fmt.Println()
	// Provision Ollama & Models
	ProvisionOllamaLocal()
	
	RunEcosystemDoctor()
}

// ProvisionOllamaLocal checks for Ollama, installs it if missing, ensures service is up, and pulls llama3.2:3b.
func ProvisionOllamaLocal() {
	fmt.Println("── 0. Local AI Service Provisioning (Ollama) ─────────────────────────")
	if _, err := exec.LookPath("ollama"); err != nil {
		fmt.Println("   [*] Ollama binary not found in PATH. Attempting automated installation...")
		cmd := exec.Command("bash", "-c", "curl -fsSL https://ollama.com/install.sh | sh")
		cmd.Env = os.Environ()
		if _, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("   ⚠️  Automated Ollama installation failed: %v\n", err)
		} else {
			fmt.Println("   ✅ Successfully installed Ollama binary via official script")
		}
	} else {
		fmt.Println("   ✔ Ollama binary found in system PATH")
	}

	// Verify or start service
	resp, err := http.Get("http://127.0.0.1:11434/api/tags")
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("   [*] Ollama service is not responding. Starting ollama serve in background...")
		_ = exec.Command("bash", "-c", "systemctl start ollama 2>/dev/null || nohup ollama serve >/dev/null 2>&1 &").Start()
		time.Sleep(3 * time.Second)
	}

	// Verify again
	resp, err = http.Get("http://127.0.0.1:11434/api/tags")
	if err == nil && resp.StatusCode == http.StatusOK {
		fmt.Println("   ✅ Ollama service is active and responding on http://127.0.0.1:11434")
		fmt.Println("   [*] Ensuring baseline model llama3.2:3b is pulled...")
		pullCmd := exec.Command("ollama", "pull", "llama3.2:3b")
		_ = pullCmd.Run()
	} else {
		fmt.Println("   ⚠️  Ollama service offline. Scan will fallback to Gemini Cloud API if configured or deterministic heuristics.")
	}
	fmt.Println()
}
