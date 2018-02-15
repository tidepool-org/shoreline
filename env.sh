export TIDEPOOL_SHORELINE_ENV='{
    "hakken": { "host": "localhost:8000" },
    "highwater": {
  	    "serviceSpec": { "type": "static", "hosts": ["http://localhost:9191"] },
  	    "name": "highwater",
        "metricsSource" : "user-api-local",
        "metricsVersion" : "v0.0.1"
    },
    "gatekeeper": { "serviceSpec": { "type": "static", "hosts": ["http://localhost:9123"] } }
}'

export TIDEPOOL_SHORELINE_SERVICE='{
  "service": {
    "service": "user-api-local",
    "protocol": "http",
    "host": "localhost:9107",
    "keyFile": "config/key.pem",
    "certFile": "config/cert.pem"
  },
  "mongo": {
    "connectionString": "mongodb://localhost/user"
  },
  "user": {
    "serverSecret": "This needs to be the same secret everywhere. YaHut75NsK1f9UKUXuWqxNN0RUwHFBCy",
    "apiSecret": "This is a local API secret for everyone. BsscSHqSHiwrBMJsEGqbvXiuIUPAjQXU",
    "longTermKey": "abcdefghijklmnopqrstuvwxyz",
    "longTermDaysDuration": 30,
    "tokenDurationSecs": 2592000,
    "salt": "ADihSEI7tOQQP9xfXMO9HfRpXKu1NpIJ",
    "verificationSecret": "+skip",
    "clinicDemoUserId": ""
  }
}'

export TIDEPOOL_SHORELINE_AUTH0_DOMAIN="https://tidepool-dev.auth0.com/"

export TIDEPOOL_SHORELINE_AUTH0_AUDIENCE="https://dev-api.tidepool.org/"

export TIDEPOOL_SHORELINE_AUTH0_PUBLICKEY="-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJKgxoovYAFWXUMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFnRpZGVwb29sLWRldi5hdXRoMC5jb20wHhcNMTcwODAzMjIyODA2WhcNMzEw
NDEyMjIyODA2WjAhMR8wHQYDVQQDExZ0aWRlcG9vbC1kZXYuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuVMoAL/XCzHyLUTXqCXKzneO
tc3QZEnClRl7d/0890/YE80v/vYqIugzmYdgwFG7xHOEf9RBu9PviYCFCUpnH47f
bfiBkTlKgLaiHgZ+5KsxM1uaQjQDel+RksaCyhQl1CXVia7f8E0KKGCI1if7ldIO
FRuMTFIDUfr2HL4vamNYGiyEBb49TgHySDSzPnxsseL3x//j/FUEeA+H6D79Ckpe
qyK+y5TMbsHcHVVRUWQCBrTD53+GefS9FGsqFivIXfWtTiTu8FyGGMNjeyod6HUm
MM5wOVRaIF7c+uapMWKy0HzP7oDFqQuS192gyjE+gp5nnbs5ZxwRQgZm4MfDGQID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQq7D85Wyjun7Y2Npex
b44O5egNaTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBABH/kV9a
WcV/fFwf23G9r8IjtUQHmu6y96IhyKHxaGPnv9HVAogq3mOWaICasXc3b/dhH+Aw
kPkViAu2D/Z/qkMX98UlZMdhSb+e71ZbqhUfqsO4CXVIiEKK/1jNrxU3KjId2q2x
CseP1OAP40Ji24R3w5bRRqnI4UpSp+1taVE/69yZHHRzu5atCo9UXz/As1iyfi51
0ZTwy6AsLjDeeYxrTCtDVr90+Klaw+wNe1S1yl/FK7h9Kqi7U3tbq7Fmctmu5L/U
WWlCPkhkNkEk+FciILEgYtvkjeyD0yfWePa1r+utiE2POQ1sh/7ZkN8pxslB6Uy9
uX25CkWJVMAx2tI=
-----END CERTIFICATE-----"