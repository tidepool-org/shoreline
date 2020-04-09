package user

import (
	"reflect"
	"testing"
	"net/http"
)

func Test_FirstStringNotEmpty_None(t *testing.T) {
	result := firstStringNotEmpty()
	if result != "" {
		t.Fatalf("Unexpected result: %#v", result)
	}
}

func Test_FirstStringNotEmpty_One(t *testing.T) {
	result := firstStringNotEmpty("one")
	if result != "one" {
		t.Fatalf("Unexpected result: %#v", result)
	}
}

func Test_FirstStringNotEmpty_Two(t *testing.T) {
	result := firstStringNotEmpty("", "two")
	if result != "two" {
		t.Fatalf("Unexpected result: %#v", result)
	}
}

func Test_FirstStringNotEmpty_Blank(t *testing.T) {
	result := firstStringNotEmpty("", "", "")
	if result != "" {
		t.Fatalf("Unexpected result: %#v", result)
	}
}

func Test_AsSerializableUser_Interface(t *testing.T) {
	serializableUser := shoreline.asSerializableUser(&User{}, false)
	if serializableUser == nil {
		t.Fatalf("Serializable user is nil")
	}
	if _, ok := serializableUser.(map[string]interface{}); !ok {
		t.Fatalf("Serializable user [%#v] does not match expected interface", serializableUser)
	}
}

func Test_AsSerializableUser_UserId(t *testing.T) {
	user := &User{Id: "1234567890"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 1 || serializableUser["userid"] != user.Id {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for userid", serializableUser, user)
	}
}

func Test_AsSerializableUser_Username(t *testing.T) {
	user := &User{Username: "tester@test.com"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 2 || serializableUser["username"] != user.Username || serializableUser["emailVerified"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for username", serializableUser, user)
	}
}

func Test_AsSerializableUser_Emails(t *testing.T) {
	user := &User{Emails: []string{"tester@test.com"}}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 2 || !reflect.DeepEqual(serializableUser["emails"], user.Emails) || serializableUser["emailVerified"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for emails", serializableUser, user)
	}
}

func Test_AsSerializableUser_Roles(t *testing.T) {
	user := &User{Roles: []string{"clinic"}}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 1 || !reflect.DeepEqual(serializableUser["roles"], user.Roles) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for roles", serializableUser, user)
	}
}

func Test_AsSerializableUser_TermsAccepted(t *testing.T) {
	user := &User{TermsAccepted: "2016-01-01T00:00:00-08:00"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 1 || serializableUser["termsAccepted"] != user.TermsAccepted {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for termsAccepted", serializableUser, user)
	}
}

func Test_AsSerializableUser_EmailVerified_True(t *testing.T) {
	user := &User{Username: "tester@test.com", EmailVerified: true}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 2 || serializableUser["username"] != user.Username || !serializableUser["emailVerified"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for emailVerified as true", serializableUser, user)
	}
}

func Test_AsSerializableUser_EmailVerified_False(t *testing.T) {
	user := &User{Username: "tester@test.com", EmailVerified: false}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 2 || serializableUser["username"] != user.Username || serializableUser["emailVerified"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for emailVerified as false", serializableUser, user)
	}
}

func Test_AsSerializableUser_PasswordExists_True_Server(t *testing.T) {
	user := &User{PwHash: "abcdefghijkl"}
	serializableUser := shoreline.asSerializableUser(user, true).(map[string]interface{})
	if len(serializableUser) != 1 || !serializableUser["passwordExists"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for passwordExists as not server", serializableUser, user)
	}
}

func Test_AsSerializableUser_PasswordExists_True_NotServer(t *testing.T) {
	user := &User{PwHash: "abcdefghijkl"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 0 {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for passwordExists as not server", serializableUser, user)
	}
}

func Test_AsSerializableUser_PasswordExists_False_Server(t *testing.T) {
	user := &User{}
	serializableUser := shoreline.asSerializableUser(user, true).(map[string]interface{})
	if len(serializableUser) != 1 || serializableUser["passwordExists"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for passwordExists as not server", serializableUser, user)
	}
}

func Test_AsSerializableUser_PasswordExists_False_NotServer(t *testing.T) {
	user := &User{}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 0 {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for passwordExists as not server", serializableUser, user)
	}
}

func resetLoginLimitConfig() {
	shoreline.ApiConfig.MaxConcurrentLogin = 100
	shoreline.ApiConfig.DelayBeforeNextLoginAttempt = 10
	shoreline.ApiConfig.BlockParallelLogin = true
	shoreline.loginLimiter.totalInProgress = 0
}
func Test_appendUserLoginInProgress_RateLimitExceeded(t *testing.T) {
	user := &User{}
	resetLoginLimitConfig()
	shoreline.loginLimiter.totalInProgress = shoreline.ApiConfig.MaxConcurrentLogin
	shoreline.loginLimiter.usersInProgress.Init()
	code, _ := shoreline.appendUserLoginInProgress(user)
	if(code != http.StatusTooManyRequests) {
		t.Fatalf("appendUserLoginInProgress should return an http too many requests error when the limit is execedded")
	}
}

func Test_appendUserLoginInProgress_UserAlreadyLoginIn(t *testing.T) {
	user := &User{Username: "test@test.com"}
	resetLoginLimitConfig()
	shoreline.loginLimiter.usersInProgress.Init()
	code, _ := shoreline.appendUserLoginInProgress(user)
	code, _ = shoreline.appendUserLoginInProgress(user)
	if(code != http.StatusTooManyRequests) {
		t.Fatalf("appendUserLoginInProgress should return an http too many requests error when the user is in the in progress list")
	}
}
func Test_appendUserLoginInProgress_NoProblem(t *testing.T) {
	user := &User{Username: "test2@test.com"}
	resetLoginLimitConfig()
	shoreline.loginLimiter.usersInProgress.Init()
	code, _ := shoreline.appendUserLoginInProgress(user)
	if(code != http.StatusOK) {
		t.Fatalf("appendUserLoginInProgress should return an http status ok when the user is not in the in progress list")
	}
	if(shoreline.loginLimiter.totalInProgress != 1) {
		t.Fatalf("appendUserLoginInProgress should increment the total login counter")
	}
	if(shoreline.loginLimiter.usersInProgress.Len() !=1){
		t.Fatalf("appendUserLoginInProgress should add users into userInProgress list")
	}
}

func Test_appendUserLoginInProgress_BlockParallelDisabled(t *testing.T) {
	user := &User{}
	resetLoginLimitConfig()
	shoreline.ApiConfig.BlockParallelLogin = false
	shoreline.loginLimiter.totalInProgress = shoreline.ApiConfig.MaxConcurrentLogin
	shoreline.loginLimiter.usersInProgress.Init()
	code, _ := shoreline.appendUserLoginInProgress(user)
	if(code != http.StatusTooManyRequests) {
		t.Fatalf("appendUserLoginInProgress should return an http too many requests error when the limit is execedded")
	}
	shoreline.loginLimiter.totalInProgress = 0
	code, _ = shoreline.appendUserLoginInProgress(user)
	if(code != http.StatusOK) {
		t.Fatalf("appendUserLoginInProgress should return an http status ok when BlockParallelLogin config is set to false")
	}
	if(shoreline.loginLimiter.totalInProgress != 1) {
		t.Fatalf("appendUserLoginInProgress should increment the total login counter")
	}
	if(shoreline.loginLimiter.usersInProgress.Len() !=0){
		t.Fatalf("appendUserLoginInProgress should leave the userInProgress list empty when BlockParallelLogin config is set to false")
	}
	code, _ = shoreline.appendUserLoginInProgress(user)
	if(code != http.StatusOK) {
		t.Fatalf("appendUserLoginInProgress should return an http status ok when BlockParallelLogin config is set to false")
	}
	if(shoreline.loginLimiter.totalInProgress != 2) {
		t.Fatalf("appendUserLoginInProgress should increment the total login counter")
	}
	if(shoreline.loginLimiter.usersInProgress.Len() !=0){
		t.Fatalf("appendUserLoginInProgress should leave the userInProgress list empty when BlockParallelLogin config is set to false")
	}
}

func Test_removeUserLoginInProgress(t *testing.T) {
	user := &User{Username: "test3@test.com"}
	resetLoginLimitConfig()
	shoreline.loginLimiter.usersInProgress.Init()
	_, elem := shoreline.appendUserLoginInProgress(user)
	shoreline.removeUserLoginInProgress(elem)
	if(shoreline.loginLimiter.totalInProgress != 0) {
		t.Fatalf("removeUserLoginInProgress should decrement the total login counter")
	}
	if(shoreline.loginLimiter.usersInProgress.Len() !=0){
		t.Fatalf("removeUserLoginInProgress should remove users from userInProgress list")
	}
}

func Test_removeUserLoginInProgress_BlockParallelDisabled(t *testing.T) {
	user := &User{Username: "test3@test.com"}
	resetLoginLimitConfig()
	shoreline.ApiConfig.BlockParallelLogin = false
	shoreline.loginLimiter.usersInProgress.Init()
	_, elem := shoreline.appendUserLoginInProgress(user)
	shoreline.removeUserLoginInProgress(elem)
	if(shoreline.loginLimiter.totalInProgress != 0) {
		t.Fatalf("removeUserLoginInProgress should decrement the total login counter")
	}
	if(shoreline.loginLimiter.usersInProgress.Len() !=0){
		t.Fatalf("removeUserLoginInProgress should leave the userInProgress list empty when BlockParallelLogin config is set to false")
	}

	_, elem = shoreline.appendUserLoginInProgress(user)
	shoreline.appendUserLoginInProgress( &User{Username: "test4@test.com"})
	shoreline.removeUserLoginInProgress(elem)
	if(shoreline.loginLimiter.totalInProgress != 1) {
		t.Fatalf("removeUserLoginInProgress should decrement the total login counter")
	}
	if(shoreline.loginLimiter.usersInProgress.Len() !=0){
		t.Fatalf("removeUserLoginInProgress should leave the userInProgress list empty when BlockParallelLogin config is set to false")
	}
}