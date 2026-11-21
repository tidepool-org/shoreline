package user

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const migrationTestSecret = "migration-test-secret"

func migrationTestShoreline(store Storage) *Api {
	config := fakeConfig
	config.MigrationSecret = migrationTestSecret
	return InitShoreline(config, store, responsableGatekeeper, mockNotifier)
}

func performMigrationLookup(t *testing.T, api *Api, username string, authorization string) *httptest.ResponseRecorder {
	request, err := http.NewRequest("GET", "/migrate/"+username, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	if authorization != "" {
		request.Header.Set("authorization", authorization)
	}
	response := httptest.NewRecorder()
	api.GetUserForMigration(response, request, map[string]string{"username": username})
	return response
}

func Test_GetUserForMigration_Unauthorized(t *testing.T) {
	store := NewResponsableMockStoreClient()
	response := performMigrationLookup(t, migrationTestShoreline(store), "old@example.org", "Bearer wrong")

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("want %d; got %d", http.StatusUnauthorized, response.Code)
	}
}

func Test_GetUserForMigration_NotYetMigrated(t *testing.T) {
	store := NewResponsableMockStoreClient()
	store.FindUsersResponses = []FindUsersResponse{{[]*User{{Id: "0123456789", Username: "user@example.org", Emails: []string{"user@example.org"}}}, nil}}
	store.FindUserResponses = []FindUserResponse{{&User{Id: "0123456789", Username: "user@example.org"}, nil}}

	response := performMigrationLookup(t, migrationTestShoreline(store), "user@example.org", "Bearer "+migrationTestSecret)

	if response.Code != http.StatusOK {
		t.Fatalf("want %d; got %d", http.StatusOK, response.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Unable to decode response body: %v", err)
	}
	if body["id"] != "0123456789" || body["username"] != "user@example.org" {
		t.Fatalf("Unexpected migration payload: %v", body)
	}
	if store.HasResponses() {
		t.Fatalf("Expected all store responses to be consumed")
	}
}

func Test_GetUserForMigration_AlreadyMigrated(t *testing.T) {
	// The legacy record still holds the old email after the user changed it in Keycloak. Returning
	// it would let the migration plugin match the Keycloak account by id and revert the change.
	store := NewResponsableMockStoreClient()
	store.FindUsersResponses = []FindUsersResponse{{[]*User{{Id: "0123456789", Username: "old@example.org", Emails: []string{"old@example.org"}}}, nil}}
	store.FindUserResponses = []FindUserResponse{{&User{Id: "0123456789", Username: "new@example.org", IsMigrated: true}, nil}}

	response := performMigrationLookup(t, migrationTestShoreline(store), "old@example.org", "Bearer "+migrationTestSecret)

	expectErrorResponse(t, response, http.StatusNotFound, STATUS_USER_NOT_FOUND)
	if store.HasResponses() {
		t.Fatalf("Expected all store responses to be consumed")
	}
}

func Test_GetUserForMigration_MigrationCheckFails(t *testing.T) {
	store := NewResponsableMockStoreClient()
	store.FindUsersResponses = []FindUsersResponse{{[]*User{{Id: "0123456789", Username: "user@example.org"}}, nil}}
	store.FindUserResponses = []FindUserResponse{{nil, errors.New("keycloak unavailable")}}

	response := performMigrationLookup(t, migrationTestShoreline(store), "user@example.org", "Bearer "+migrationTestSecret)

	expectErrorResponse(t, response, http.StatusInternalServerError, STATUS_ERR_FINDING_USR)
}
