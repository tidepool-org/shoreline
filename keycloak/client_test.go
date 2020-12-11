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
