package phases

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mohammed-v3/core/pkg/engine"
	"github.com/mohammed-v3/core/pkg/filter"
	"github.com/mohammed-v3/core/pkg/governor"
)

// TakeoverResolverPhase inspects CNAME records for all discovered subdomains,
// queries public DNS and target HTTP responses, and cross-references against
// high-confidence SaaS / Cloud abandonment signatures to detect dangling domain takeovers.
type TakeoverResolverPhase struct{}

func (p *TakeoverResolverPhase) Name() string { return "Dangling CNAME Takeover Resolver" }
func (p *TakeoverResolverPhase) Description() string {
	return "DNS CNAME mapping & fingerprint verification against cloud service abandonment signatures"
}

// TakeoverFingerprint defines signature matches for abandoned cloud resources.
type TakeoverFingerprint struct {
	Service      string
	CNAMESuffix  string
	Signatures   []string
	HTTPStatus   int // Optional expected HTTP status (0 = any)
}

var knownTakeoverFingerprints = []TakeoverFingerprint{
	{
		Service:     "AWS S3",
		CNAMESuffix: ".s3.amazonaws.com",
		Signatures: []string{
			"NoSuchBucket",
			"The specified bucket does not exist",
		},
		HTTPStatus: http.StatusNotFound,
	},
	{
		Service:     "GitHub Pages",
		CNAMESuffix: "github.io",
		Signatures: []string{
			"There isn't a GitHub Pages site here",
			"For root URLs (like http://example.com/) you must provide an index.html file",
		},
		HTTPStatus: http.StatusNotFound,
	},
	{
		Service:     "Heroku",
		CNAMESuffix: "herokudns.com",
		Signatures: []string{
			"No such app",
			"herokucdn.com/error-pages/no-such-app.html",
		},
		HTTPStatus: http.StatusNotFound,
	},
	{
		Service:     "Heroku Legacy",
		CNAMESuffix: "herokuapp.com",
		Signatures: []string{
			"No such app",
			"herokucdn.com/error-pages/no-such-app.html",
		},
		HTTPStatus: http.StatusNotFound,
	},
	{
		Service:     "Azure Traffic Manager",
		CNAMESuffix: "trafficmanager.net",
		Signatures: []string{
			"404 Web Site not found",
		},
		HTTPStatus: http.StatusNotFound,
	},
	{
		Service:     "Azure CloudApp",
		CNAMESuffix: "cloudapp.net",
		Signatures: []string{
			"404 Web Site not found",
		},
		HTTPStatus: http.StatusNotFound,
	},
	{
		Service:     "Zendesk",
		CNAMESuffix: "zendesk.com",
		Signatures: []string{
			"Help Center Closed",
		},
		HTTPStatus: http.StatusNotFound,
	},
	{
		Service:     "Fastly",
		CNAMESuffix: "fastly.net",
		Signatures: []string{
			"Fastly error: unknown domain",
		},
		HTTPStatus: http.StatusNotFound,
	},
	{
		Service:     "CloudFront",
		CNAMESuffix: "cloudfront.net",
		Signatures: []string{
			"Bad request: ERROR: The request could not be satisfied",
		},
		HTTPStatus: http.StatusBadRequest,
	},
}

func (p *TakeoverResolverPhase) Execute(ctx context.Context, s *engine.State) error {
	targets := s.Subdomains
	if len(targets) == 0 {
		targets = s.LiveHosts
	}

	if len(targets) == 0 {
		s.Printf("│  Takeover Resolver: SKIP (no subdomains or live hosts)\n")
		return nil
	}

	s.Printf("│  Takeover Resolver: resolving CNAME records across %d subdomains\n", len(targets))

	gov := governor.NewGovernor(2,
		governor.WithMaxRPS(2.0),
		governor.WithConcurrency(2),
		governor.WithJitter(100*time.Millisecond, 200*time.Millisecond),
	)

	client := gov.WrapClient(&http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	})

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4) // DNS / HTTP verification semaphore

	for _, sub := range targets {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		cleanSub := strings.TrimSpace(sub)
		cleanSub = strings.TrimPrefix(cleanSub, "https://")
		cleanSub = strings.TrimPrefix(cleanSub, "http://")
		cleanSub = strings.Split(cleanSub, "/")[0]
		cleanSub = strings.Split(cleanSub, ":")[0]

		if cleanSub == "" || !filter.IsInScope(cleanSub, s.Scope) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			p.checkSubdomainTakeover(ctx, s, host, client)
		}(cleanSub)
	}
	wg.Wait()

	return nil
}

func (p *TakeoverResolverPhase) checkSubdomainTakeover(ctx context.Context, s *engine.State, host string, client *http.Client) {
	// 1. Resolve CNAME using standard resolver
	cname, err := net.LookupCNAME(host)
	if err != nil {
		return
	}
	cname = strings.TrimRight(cname, ".")
	if cname == "" || strings.EqualFold(cname, host) {
		return
	}

	// 2. Cross-reference CNAME with known service fingerprints
	var matchedFP *TakeoverFingerprint
	for _, fp := range knownTakeoverFingerprints {
		if strings.HasSuffix(strings.ToLower(cname), strings.ToLower(fp.CNAMESuffix)) {
			matchedFP = &fp
			break
		}
	}

	if matchedFP == nil {
		return
	}

	// 3. Send HTTP request to verify abandonment signatures
	probeURLs := []string{"https://" + host, "http://" + host}
	for _, targetURL := range probeURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(bodyBytes)
		for _, sig := range matchedFP.Signatures {
			if strings.Contains(bodyStr, sig) {
				s.AddFinding(map[string]interface{}{
					"title":          fmt.Sprintf("Subdomain Takeover: %s -> %s", host, cname),
					"severity":       "High",
					"url":            targetURL,
					"evidence":       fmt.Sprintf("CNAME %q matches service %s abandonment signature: %q (HTTP %d)", cname, matchedFP.Service, sig, resp.StatusCode),
					"tool":           "takeover_resolver",
					"confidence":     90,
					"http_confirmed": true,
				})
				return
			}
		}
	}
}
