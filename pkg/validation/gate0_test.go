package validation

import "testing"

// TestV123_IsPublicUnauthenticatedRoute is the FAILURE #6 proof: every public
// route that the GitLab scan wrongly flagged as IDOR/Race/CORS/Auth MUST be
// rejected by Gate 0, while a genuine authenticated object route MUST pass
// through (return false = not public).
func TestV123_IsPublicUnauthenticatedRoute(t *testing.T) {
	public := []string{
		"https://gitlab.com/explore/projects",
		"https://gitlab.com/explore/topics",
		"https://gitlab.com/blog/tags/security",
		"https://docs.gitlab.com/ee/",
		"https://about.gitlab.com/handbook/engineering/",
		"https://gitlab.com/help/user/index",
		"https://about.gitlab.com/pricing/",
		"https://gitlab.com/explore/projects?sort=latest_activity_desc",
		"https://gitlab.com/dashboard/projects?archived=true",
		"https://gitlab.com/explore?language=go",
	}
	for _, u := range public {
		if !IsPublicUnauthenticatedRoute(u, "") {
			t.Errorf("expected PUBLIC route to be rejected by Gate 0: %q", u)
		}
	}

	// Genuine authenticated / object-scoped routes must NOT be treated as
	// public (Gate 0 returns false → the engine may proceed to test them).
	private := []string{
		"https://gitlab.com/api/v4/user",
		"https://gitlab.com/groups/acme/-/settings/members",
		"https://gitlab.com/acme/backend/-/merge_requests/42",
		"https://gitlab.com/api/v4/projects/123/access_tokens",
	}
	for _, u := range private {
		if IsPublicUnauthenticatedRoute(u, "") {
			t.Errorf("private/object route wrongly classified public by Gate 0: %q", u)
		}
	}
}

// TestV123_ValidateAdminEndpointAccess is the FAILURE #7 proof: JS/CSS/map
// assets and docs/handbook pages must NEVER be classified as unauthenticated
// admin access, while a real, unauthenticated 200 admin panel with actual admin
// controls MUST be accepted.
func TestV123_ValidateAdminEndpointAccess(t *testing.T) {
	adminBody := "<h1>Admin Dashboard</h1><button>Delete user</button><a>Impersonate</a>"

	cases := []struct {
		name string
		req  AdminAccessRequest
		resp AdminAccessResponse
		want bool
	}{
		{
			name: "js bundle with admin in path is NOT admin",
			req:  AdminAccessRequest{URL: "https://gitlab.com/assets/admin-abc123.js"},
			resp: AdminAccessResponse{StatusCode: 200, Body: adminBody},
			want: false,
		},
		{
			name: "ts source is NOT admin",
			req:  AdminAccessRequest{URL: "https://gitlab.com/app/admin/panel.ts"},
			resp: AdminAccessResponse{StatusCode: 200, Body: adminBody},
			want: false,
		},
		{
			name: "sourcemap is NOT admin",
			req:  AdminAccessRequest{URL: "https://gitlab.com/x/admin.js.map"},
			resp: AdminAccessResponse{StatusCode: 200, Body: adminBody},
			want: false,
		},
		{
			name: "docs host about administration is NOT admin",
			req:  AdminAccessRequest{URL: "https://docs.gitlab.com/ee/administration/"},
			resp: AdminAccessResponse{StatusCode: 200, Body: adminBody},
			want: false,
		},
		{
			name: "docs path is NOT admin",
			req:  AdminAccessRequest{URL: "https://gitlab.com/docs/administration/settings"},
			resp: AdminAccessResponse{StatusCode: 200, Body: adminBody},
			want: false,
		},
		{
			name: "html page but body has NO admin controls",
			req:  AdminAccessRequest{URL: "https://gitlab.com/admin"},
			resp: AdminAccessResponse{StatusCode: 200, Body: "<html>Please sign in to continue</html>"},
			want: false,
		},
		{
			name: "authenticated request is NOT unauthenticated access",
			req:  AdminAccessRequest{URL: "https://gitlab.com/admin", HasAuthCookies: true},
			resp: AdminAccessResponse{StatusCode: 200, Body: adminBody},
			want: false,
		},
		{
			name: "non-200 status is NOT confirmed access",
			req:  AdminAccessRequest{URL: "https://gitlab.com/admin"},
			resp: AdminAccessResponse{StatusCode: 403, Body: adminBody},
			want: false,
		},
		{
			name: "GENUINE unauth admin panel with real controls",
			req:  AdminAccessRequest{URL: "https://gitlab.com/admin"},
			resp: AdminAccessResponse{StatusCode: 200, Body: adminBody},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidateAdminEndpointAccess(tc.req, tc.resp); got != tc.want {
				t.Fatalf("ValidateAdminEndpointAccess(%q) = %v, want %v", tc.req.URL, got, tc.want)
			}
		})
	}
}

// TestV124_PublicCatalogReadRejection is the FAILURE #8 proof: the exact ICI
// PARIS XL catalog endpoints that Phase 33 (IDOR) and Phase 47 (Financial)
// wrongly flagged MUST be rejected by Gate 0 as public catalog reads, while
// genuine account/order/payment object routes MUST still pass through.
func TestV124_PublicCatalogReadRejection(t *testing.T) {
	publicCatalog := []string{
		"https://api.iciparisxl.nl/api/v2/icinl2/breadcrumbs?code=1252879&curr=EUR&lang=nl_NL&pageId=productDetailsSPR_icinl2",
		"https://api.iciparisxl.be/api/v2/icibe2/catalogs/brands?codes=1094&curr=EUR&fields=DEFAULT&lang=fr_BE",
		"https://api.iciparisxl.nl/api/v2/icinl2/products/BP_1175033/paginatedReviews?currentPage=0&pageSize=5&lang=nl_NL&curr=EUR",
		"https://api.iciparisxl.nl/api/v2/icinl2/redirects/parfum/c/2?lang=nl_NL&curr=EUR",
		"https://api.iciparisxl.nl/api/v2/icinl3/search?curr=EUR&fields=FULL&lang=nl_NL&query=la+poche",
		"https://api.iciparisxl.nl/api/v2/icinl3/enhance-reviews/BP_1240042/images?curr=EUR&currentPage=1&lang=nl_NL&pageSize=100",
		"https://api.iciparisxl.be/api/v2/icibe2/configurations?curr=EUR&key=criteo.enabled.content.pages&lang=fr_BE",
	}
	for _, u := range publicCatalog {
		if !IsPublicUnauthenticatedRoute(u, "") {
			t.Errorf("expected PUBLIC catalog read to be rejected by Gate 0: %q", u)
		}
	}

	// Account / order / payment object routes cross an authorization boundary
	// and MUST NOT be suppressed — even when a catalog token also appears in
	// the path (the account boundary wins).
	private := []string{
		"https://api.iciparisxl.nl/api/v2/icinl2/users/42/orders",
		"https://api.iciparisxl.nl/api/v2/icinl2/carts/current/entries",
		"https://api.iciparisxl.be/api/v2/icibe2/customers/me/paymentdetails",
		"https://api.iciparisxl.nl/api/v2/icinl2/users/7/wishlist/products", // catalog token 'products' but account boundary 'users' wins
		"https://api.iciparisxl.nl/api/v2/icinl2/orders/BP_1/invoice",
	}
	for _, u := range private {
		if IsPublicUnauthenticatedRoute(u, "") {
			t.Errorf("account/order route wrongly classified public by Gate 0: %q", u)
		}
	}
}
