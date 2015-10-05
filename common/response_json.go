package common

import (
	"encoding/json"
	"net/http"
)

// outputJSON encodes the Response to JSON and writes to the http.ResponseWriter
func OutputJSON(w http.ResponseWriter, status int, data map[string]interface{}) error {
	// Output json
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	err := encoder.Encode(data)
	if err != nil {
		return err
	}
	return nil
}
