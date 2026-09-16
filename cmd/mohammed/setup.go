package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ZeroAPIEcosystem represents the 10 essential tools for passive & active reconnaissance,
// content/parameter discovery, and secret scanning without requiring paid commercial APIs.
type ToolSpec struct {
	Name        string
	Category    string
	Description string
	GoPackage   string
	InstallCmd  string // Optional alternative installer command
}

var EssentialEcosystem = []ToolSpec{
	// 1. Recon & Probing
	{
		Name:        "subfinder",
		Category:    "Recon & Discovery",
		Description: "Fast passive subdomain enumeration via public OSINT sources",
		GoPackage:   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
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
	},
	{
		Name:        "ffuf",
		Category:    "Fuzzing & Content",
		Description: "Fast web fuzzer written in Go for paths, virtual hosts, and parameters",
		GoPackage:   "github.com/ffuf/ffuf/v2@latest",
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
	},
}

// RunEcosystemSetup executes the automated installation of all 10 tools.
func RunEcosystemSetup() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║     MOHAMMED-V4 ZERO-API HYBRID ECOSYSTEM SETUP & INSTALLER       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Ensure $GOPATH/bin is in PATH for current process
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		home, _ := os.UserHomeDir()
		goPath = home + "/go"
	}
	goBin := goPath + "/bin"
	currPath := os.Getenv("PATH")
	if !strings.Contains(currPath, goBin) {
		_ = os.Setenv("PATH", goBin+":"+currPath)
	}

	fmt.Printf("[*] Target Go Binary Directory: %s\n\n", goBin)

	success := 0
	failed := 0

	for idx, tool := range EssentialEcosystem {
		fmt.Printf("[%d/%d] Installing %-12s (%s)...\n", idx+1, len(EssentialEcosystem), tool.Name, tool.Category)

		var cmd *exec.Cmd
		if tool.GoPackage != "" {
			cmd = exec.Command("go", "install", "-v", tool.GoPackage)
		} else if tool.InstallCmd != "" {
			cmd = exec.Command("bash", "-c", tool.InstallCmd)
		}

		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("   ❌ Failed to install %s: %v\n", tool.Name, err)
			if len(out) > 0 {
				lines := strings.Split(string(out), "\n")
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						fmt.Printf("      %s\n", line)
					}
				}
			}
			failed++
		} else {
			fmt.Printf("   ✅ Successfully installed %s\n", tool.Name)
			success++
		}
	}

	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Printf("[+] Setup Complete: %d installed, %d failed\n", success, failed)
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println("[*] Launching system health doctor check...")
	fmt.Println()
	RunEcosystemDoctor()
}
