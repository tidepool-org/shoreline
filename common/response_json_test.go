package common

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type (
	One struct {
		Id   string `json:"oneId"`
		Name string `json:"oneName"`
	}

	Many []*One
)

func TestResponseJSON(t *testing.T) {

	w := httptest.NewRecorder()

	myOne := &One{Id: "123", Name: "Some Name"}
	data := make(map[string]interface{})
	data["people"] = myOne

	err := OutputJSON(w, http.StatusOK, data)
	if err != nil {
		t.Fatalf("Error outputting json: %s", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("Invalid response code for output: %d", w.Code)
	}

	if w.HeaderMap.Get("Content-Type") != "application/json" {
		t.Fatalf("Result from json must be application/json")
	}

	output := make(map[string]One)
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not decode output json: %s", err)
	}

	if d, ok := output["people"]; !ok || d.Id != myOne.Id || d.Name != myOne.Name {
		t.Fatalf("Invalid or not found output data= %s", d)
	}
}

func TestResponseJSON_many(t *testing.T) {

	w := httptest.NewRecorder()

	data := make(map[string]interface{})
	many := Many{&One{Id: "123", Name: "Some Name"}, &One{Id: "456", Name: "Some Other Name"}}
	data["people"] = many

	err := OutputJSON(w, http.StatusOK, data)
	if err != nil {
		t.Fatalf("Error outputting json: %s", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("Invalid response code for output: %d", w.Code)
	}

	if w.HeaderMap.Get("Content-Type") != "application/json" {
		t.Fatalf("Result from json must be application/json")
	}

	output := make(map[string]Many)
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not decode output json: %s", err)
	}

	if d, ok := output["people"]; !ok || d[0].Id != many[0].Id || d[1].Id != many[1].Id {
		t.Fatalf("Invalid or not found output data= %v", d)
	}
}

func TestErrorResponseJSON(t *testing.T) {

	w := httptest.NewRecorder()

	anError := errors.New("Whoops we are mising the BIG param")
	data := make(map[string]interface{})
	data["error"] = anError.Error()

	err := OutputJSON(w, http.StatusExpectationFailed, data)
	if err != nil {
		t.Fatalf("Error outputting json: %s", err)
	}

	//fmt.Printf("%d - %s - %+v", w.Code, w.Body.String(), w.HeaderMap)

	if w.Code != http.StatusExpectationFailed {
		t.Fatalf("Invalid response code for error output: %d", w.Code)
	}

	if w.HeaderMap.Get("Content-Type") != "application/json" {
		t.Fatalf("Result from json must be application/json")
	}

	// parse output json
	output := make(map[string]interface{})
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not decode output json: %s", err)
	}

	if d, ok := output["error"]; !ok || d != anError.Error() {
		t.Fatalf("Invalid or not found output data: error=%s", d)
	}
}
