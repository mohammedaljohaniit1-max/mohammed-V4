package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mohammed-v3/core/pkg/config"
	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/phases"
	"github.com/mohammed-v3/core/pkg/runner"
)

const banner = `
███╗   ███╗ ██████╗ ██╗  ██╗ █████╗ ███╗   ███╗███╗   ███╗███████╗██████╗ 
████╗ ████║██╔═══██╗██║  ██║██╔══██╗████╗ ████║████╗ ████║██╔════╝██╔══██╗
██╔████╔██║██║   ██║███████║███████║██╔████╔██║██╔████╔██║█████╗  ██║  ██║
██║╚██╔╝██║██║   ██║██╔══██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║██╔══╝  ██║  ██║
██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗██████╔╝
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═════╝ 
                                                     v3 | Ultimate Recon Engine
`

const helpText = `
MOHAMMED v4 — Ultimate Security Reconnaissance & Vulnerability Discovery Framework

USAGE:
  ./mohammed <command> [flags]

COMMANDS:
  scan       Run recon + vulnerability scan with target-size profiles
  doctor     Check tool availability and PATH environment
  setup      Automated one-click installation of all 38+ scanning tools
  help       Show this guidance menu

TARGET SIZING RECOMMENDATIONS:

  1. 🔴 LARGE / BUG BOUNTY TARGETS (e.g. HackerOne / Bugcrowd Large Scope)
     Use the 'large' or 'bugbounty' profile for deep recursive discovery (bbot, amass, full crawl, all vulns):
     👉 ./mohammed scan -s scope.txt -c config.yaml --profile large --burp http://172.30.48.1:8080

  2. 🟡 MEDIUM TARGETS (Standard Company Scope / 10-50 Subdomains)
     Use the 'medium' profile for balanced speed and comprehensive scanning:
     👉 ./mohammed scan -s scope.txt -c config.yaml --profile medium

  3. 🟢 SMALL TARGETS (Simple Single Web App / Few Endpoints)
     Use the 'small' profile for fast, targeted discovery without heavy bruteforcing:
     👉 ./mohammed scan -s scope.txt -c config.yaml --profile small

  4. 🔵 PASSIVE RECON ONLY (Zero Active Scanning / Safe OSINT)
     Use the 'passive' profile to gather subdomains and archives without sending active payloads:
     👉 ./mohammed scan -s scope.txt -c config.yaml --profile passive

SCAN FLAGS:
  -s, --scope     string   Path to scope file (required)
  -c, --config    string   Path to config.yaml file with API keys (default: config.yaml)
  --profile       string   Scan profile: small | medium | large | passive (default: medium)
  --burp          string   Burp Suite proxy URL (e.g. http://172.30.48.1:8080)
  --skip          int      Skip to phase number (0 = start from beginning)
  --threads       int      Global thread count (default: 30)
  --rate          int      Requests per minute (default: 150)
  --output        string   Output directory (default: output/)
`

var allTools = []string{
	"subfinder", "amass", "bbot", "assetfinder", "findomain",
	"dnsx", "puredns", "massdns", "shuffledns",
	"subzy", "httpx", "tlsx", "naabu", "nmap",
	"gau", "waybackurls", "katana", "gospider", "hakrawler",
	"getJS", "paramspider", "arjun",
	"ffuf", "feroxbuster", "dirsearch",
	"nuclei", "dalfox", "kxss",
	"sqlmap", "ghauri",
	"dontgo403", "kr", "crlfuzz", "smuggler",
	"cloud_enum", "s3scanner",
	"curl", "dig", "git",
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(banner)
		fmt.Print(helpText)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "help", "--help", "-h":
		fmt.Print(banner)
		fmt.Print(helpText)

	case "doctor":
		fmt.Print(banner)
		runDoctor()

	case "setup":
		fmt.Print(banner)
		runSetup()

	case "scan":
		fmt.Print(banner)
		runScan(os.Args[2:])

	default:
		fmt.Printf("Unknown command: %s\nRun './mohammed help' for usage.\n", os.Args[1])
		os.Exit(1)
	}
}

func runDoctor() {
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║         TOOL AVAILABILITY CHECK      ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println()

	available := 0
	missing := 0

	for _, tool := range allTools {
		path, err := runner.ResolveToolPath(tool)
		if err == nil {
			fmt.Printf("  ✅ %-25s %s\n", tool, path)
			available++
		} else {
			fmt.Printf("  ❌ %-25s not found\n", tool)
			missing++
		}
	}

	fmt.Printf("\n  Available: %d | Missing: %d | Total: %d\n", available, missing, len(allTools))
	if missing > 0 {
		fmt.Println("\n  Run './mohammed setup' or 'bash setup.sh' to install missing tools.")
	}
}

func runSetup() {
	fmt.Println("[+] Executing Automated Tool Installer (setup.sh)...")
	setupPath := "./setup.sh"
	if _, err := os.Stat(setupPath); err != nil {
		fmt.Println("[!] Error: setup.sh not found in current directory.")
		return
	}

	cmd := exec.Command("bash", setupPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("[!] Setup completed with warnings/errors: %v\n", err)
	} else {
		fmt.Println("\n[+] Setup completed successfully!")
	}
	runDoctor()
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	scopeFile := fs.String("s", "", "Scope file path")
	fs.StringVar(scopeFile, "scope", "", "Scope file path")
	configFile := fs.String("c", "config.yaml", "Config file path with API keys")
	fs.StringVar(configFile, "config", "config.yaml", "Config file path with API keys")
	profile := fs.String("profile", "medium", "Scan profile: small | medium | large | passive")
	burp := fs.String("burp", "", "Burp Suite proxy URL")
	skip := fs.Int("skip", 0, "Skip to phase number")
	threads := fs.Int("threads", 30, "Thread count")
	rate := fs.Int("rate", 150, "Rate limit (req/min)")
	output := fs.String("output", "output", "Output directory")
	fs.Parse(args)

	if *scopeFile == "" {
		fmt.Println("[!] Error: scope file required. Use -s scope.txt")
		os.Exit(1)
	}

	scope, err := config.LoadScope(*scopeFile)
	if err != nil {
		fmt.Printf("[!] Failed to load scope: %v\n", err)
		os.Exit(1)
	}
	if len(scope.Domains) == 0 && len(scope.IPs) == 0 {
		fmt.Println("[!] Scope file is empty or has no valid targets")
		os.Exit(1)
	}

	yamlCfg, _ := config.LoadYAMLConfig(*configFile)
	if _, err := os.Stat(*configFile); err == nil {
		fmt.Printf("[+] Loaded configuration & API keys from: %s\n", *configFile)
	}

	cfg := &config.Config{
		ScopeFile: *scopeFile,
		Profile:   *profile,
		BurpProxy: *burp,
		OutputDir: *output,
		Threads:   *threads,
		RateLimit: *rate,
		APIKeys:   yamlCfg.APIKeys,
		Ollama:    yamlCfg.Ollama,
	}

	config.EnsureDir(*output)

	state := engine.NewState(cfg, scope)
	orch := engine.NewOrchestrator(state)

	allPhases := []engine.Phase{
		&phases.ScopeValidationPhase{},    // 01
		&phases.OSINTPhase{},              // 02
		&phases.SubdomainPassivePhase{},   // 03
		&phases.SubdomainActivePhase{},    // 04
		&phases.DNSResolvePhase{},         // 05
		&phases.TakeoverPhase{},           // 06
		&phases.HTTPProbePhase{},          // 07
		&phases.TLSAnalysisPhase{},        // 08
		&phases.PortScanPhase{},           // 09
		&phases.WaybackPhase{},            // 10
		&phases.CrawlPhase{},              // 11
		&phases.JSAnalysisPhase{},         // 12
		&phases.ParamDiscoveryPhase{},     // 13
		&phases.CORSPhase{},               // 14
		&phases.CloudReconPhase{},         // 15
		&phases.FuzzingPhase{},            // 16
		&phases.VulnScanPhase{},           // 17
		&phases.XSSPhase{},                // 18
		&phases.SQLiPhase{},               // 19
		&phases.SSRFPhase{},               // 20
		&phases.OpenRedirectPhase{},       // 21
		&phases.ForbiddenBypassPhase{},    // 22
		&phases.APIDiscoveryPhase{},       // 23
		&phases.CRLFPhase{},               // 24
		&phases.SmugglingPhase{},          // 25
		&phases.GitExposurePhase{},        // 26
		&phases.EmailSecurityPhase{},      // 27
		&phases.PrototypePollutionPhase{}, // 28
		&phases.ReportPhase{},             // 29
	}

	activeProfile := strings.ToLower(*profile)
	if activeProfile == "bugbounty" {
		activeProfile = "large"
	}

	for i, p := range allPhases {
		if i < *skip {
			continue
		}

		include := true
		switch activeProfile {
		case "small":
			smallPhases := map[int]bool{0: true, 2: true, 4: true, 6: true, 7: true, 11: true, 16: true, 25: true, 28: true}
			include = smallPhases[i]
		case "passive":
			passivePhases := map[int]bool{0: true, 1: true, 2: true, 4: true, 6: true, 7: true, 9: true, 11: true, 12: true, 26: true, 28: true}
			include = passivePhases[i]
		case "medium", "large", "full":
			include = true
		}

		if include {
			orch.RegisterPhase(p)
		}
	}

	if _, err := os.Stat(*configFile); err == nil {
		data, _ := os.ReadFile(*configFile)
		os.WriteFile(filepath.Join(state.OutputFolder, "config.yaml"), data, 0644)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n\n[!] Scan interrupted by user. Saving progress...")
		cancel()
	}()

	fmt.Printf("[+] Target Sizing Profile Selected: [%s]\n", strings.ToUpper(activeProfile))

	if err := orch.Run(ctx); err != nil {
		fmt.Printf("\n[!] Scan error: %v\n", err)
	}
	fmt.Printf("\n[+] Scan complete. Results in: %s/\n", state.OutputFolder)
}
