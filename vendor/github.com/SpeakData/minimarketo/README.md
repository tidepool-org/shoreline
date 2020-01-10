# MiniMarketo

[![GoDoc](https://godoc.org/github.com/SpeakData/minimarketo?status.svg)](https://godoc.org/github.com/SpeakData/minimarketo)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/SpeakData/minimarketo/master/LICENSE)

Inspired by the [FrenchBen/goketo](https://github.com/FrenchBen/goketo), we created MiniMarketo which is a very tiny client for Marketo REST API.

It is very different from goketo as it doesn't do much.

What MiniMarketo does is only one thing:

- No explicit calls to authenticate. MiniMarketo takes care of that. This means you can call REST endpoints without getting an auth token or re-authenticating when the token expires.

Other than that, MiniMarketo acts very much like a http client. So all you have to do is:
- use MiniMarketo client to call a URL along with data if needed
- define JSON struct and parse result

MiniMarketo, instead of covering all the Marketo REST API calls, acts as a thin wrapper for Marketo REST API. Currently it only supports JSON API. Most "bulk" endpoints are not supported as it requires sending and downloading files.

## Installation

```bash
go get github.com/SpeakData/minimarketo
```

## Usage

Basic operations are:
1. Create a client
2. Make a http call (Marketo API only supports GET, POST, DELETE) with url string and data in []byte if needed
3. Check "success" and parse "result" with your struct

First, create a client.
In this example, I'm passing configuration through environment variables.
```go
config := minimarketo.ClientConfig{
    ID:       os.Getenv("MARKETO_ID"),
    Secret:   os.Getenv("MARKETO_SECRET"),
    Endpoint: os.Getenv("MARKETO_URL"), // https://XXX-XXX-XXX.mktorest.com
    Debug:    true,
}
client, err := minimarketo.NewClient(config)
if err != nil {
    log.Fatal(err)
}
```

Then, call Marketo supported http calls: GET, POST, or DELETE.

Find a lead
```go
path := "/rest/v1/leads.json?"
v := url.Values{
    "filterType":   {"email"},
    "filterValues": {"tester@example.com"},
    "fields":       {"email"},
}
response, err := client.Get(path + v.Encode())
if err != nil {
    log.Fatal(err)
}
if !response.Success {
    log.Fatal(response.Errors)
}
var leads []minimarketo.LeadResult
if err = json.Unmarshal(response.Result, &leads); err != nil {
    log.Fatal(err)
}
for _, lead := range leads {
    fmt.Printf("%+v", lead)
}
```

Create a lead
```go
path := "/rest/v1/leads.json"
type Input struct {
    Email     string `json:"email"`
    FirstName string `json:"firstName"`
    LastName  string `json:"lastName"`
}
type CreateData struct {
    Action      string  `json:"action"`
    LookupField string  `json:"lookupField"`
    Input       []Input `json:"input"`
}
data := CreateData{
    "createOnly",
    "email",
    []Input{
        Input{"tester@example.com", "John", "Doe"},
    },
}

dataInBytes, err := json.Marshal(data)
response, err := client.Post(path, dataInBytes)
if err != nil {
    log.Fatal(err)
}
if !response.Success {
    log.Fatal(response.Errors)
}
var createResults []minimarketo.RecordResult
if err = json.Unmarshal(response.Result, &createResults); err != nil {
    log.Fatal(err)
}
for _, result := range createResults {
    fmt.Printf("%+v", result)
}
```

## JSON Response

MiniMarketo defines the common Marketo response format.
This covers most of the API responses.

```go
type Response struct {
	RequestID     string `json:"requestId"`
	Success       bool   `json:"success"`
	NextPageToken string `json:"nextPageToken,omitempty"`
	MoreResult    bool   `json:"moreResult,omitempty"`
	Errors        []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
	Warnings []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"warning,omitempty"`
}
```

Your job is to parse "Result".

As for convenience, MiniMarketo defines two commonly used "result" format.

```go
// Find lead returns "result" in this format
type LeadResult struct {
	ID        int    `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Created   string `json:"createdAt"`
	Updated   string `json:"updatedAt"`
}

// Create/update lead uses this format
type RecordResult struct {
	ID      int    `json:"id"`
	Status  string `json:"status"`
	Reasons []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"reasons,omitempty"`
}
```

## License

MIT

