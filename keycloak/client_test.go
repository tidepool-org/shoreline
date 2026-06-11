package keycloak

import "testing"

func Test_IntrospectionResult_IsServerToken_Success(t *testing.T) {
	result := &TokenIntrospectionResult{
		RealmAccess: RealmAccess{
			Roles: []string{"backend_service"},
		},
	}

	if result.IsServerToken() != true {
		t.Fatal("Expected token with service role to be server token")
	}
}

func Test_IdentityProviderDisplayName_PrefersConfiguredName(t *testing.T) {
	if name := identityProviderDisplayName("azure-ad", "Corporate Azure AD"); name != "Corporate Azure AD" {
		t.Fatalf("Expected configured display name, got %q", name)
	}
}

func Test_IdentityProviderDisplayName_HumanizesAlias(t *testing.T) {
	cases := map[string]string{
		"google-tidepool": "Google Tidepool",
		"auth0_saml":      "Auth0 Saml",
		"OKTA":            "Okta",
		"---":             "---", // no alphanumeric words: alias returned as-is
	}
	for alias, expected := range cases {
		if name := identityProviderDisplayName(alias, ""); name != expected {
			t.Fatalf("Expected %q to humanize to %q, got %q", alias, expected, name)
		}
	}
}
