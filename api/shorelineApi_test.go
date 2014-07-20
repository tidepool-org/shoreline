package api

import (
	clients "github.com/tidepool-org/shoreline/clients"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateUserReturnsWith400StatusWithNoParamsGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.CreateUser(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "400", response.Code)
	}
}

func TestCreateUserReturnsStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)

	request.URL.Query().Add("username", "test")
	request.URL.Query().Add("emails", "test@foo.bar")
	request.URL.Query().Add("password", "123youknoWm3")

	response := httptest.NewRecorder()

	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.CreateUser(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "400", response.Code)
	}
}

func TestUpdateUserReturns401WithNoToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.UpdateUser(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestUpdateUserRequiresWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set("x-tidepool-session-token", "blah-blah-123-blah")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.UpdateUser(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestGetUserInfoReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set("x-tidepool-session-token", "blah-blah-123-blah")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.GetUserInfo(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestGetUserInfoReturns401WithNoToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.GetUserInfo(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestDeleteUserReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set("x-tidepool-session-token", "blah-blah-123-blah")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.DeleteUser(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestDeleteUserReturns401WhenNoSessionTokenHeaderGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.DeleteUser(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestLoginReturnsWithStatus400(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.Login(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "400", response.Code)
	}
}

func TestLoginReturnsWithStatusWhenAuthorizationSet(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.SetBasicAuth("username", "password")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.Login(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestServerLoginReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestRefreshSessionReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.RefreshSession(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestValidateLongtermReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ValidateLongterm(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestRequireServerTokenReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set("x-tidepool-session-token", "blah-blah-123-blah")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.RequireServerToken(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestRequireServerToken401WhenNoSessionTokenHeaderGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.RequireServerToken(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestServerCheckTokenReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ServerCheckToken(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestLogoutReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.Logout(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestAnonymousIdHashPairReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.AnonymousIdHashPair(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestManageIdHashPairReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ManageIdHashPair(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}
