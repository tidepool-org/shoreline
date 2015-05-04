Tidepool's OAuth 2.0
=========

Apps connect to Tidepool using OAuth 2.0, the standard used by most APIs for authenticating and authorizing users.

# Initial Setup

Before you can start using OAuth2 with your application, you’ll need to tell Tidepool a bit of information about your application

## Register your application here.

``http://localhost:8009/oauth/signup``

Tell us about the app
* Set your application name
* Set your redirect uri

Create a platform user
* email
* password

```
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'usr_name=Docs+Example&uri=http%3A%2F%2Flocalhost%3A14000&email=docs%40tidepool.org&password=docs4life&password_confirm=docs4life' http://localhost:8009/auth/oauth2/signup
```

Make a note of both your client_id and client_secret.

```
client_id=d995aaabe7
client_secret=dd85baba6e0816662e4b16d32242f6526cf3e35a
```

### Notes:

* What is a platfrom user?
 * This is your applications account on the Tidepool platfrom

* What is the redirect URI?
 * The redirect URI is the URL within your application that will receive the OAuth2 credentials.

* Scopes available:
  * Requests uploading of data on behalf
  * Requests viewing of data on behalf


# Authorizing

First, direct your user to ``http://localhost:8009/oauth/authorize`` through a ``GET`` request with the following parameters:

## Parameters:

For ``GET`` include them as query parameters remembering to please URL encode the parameters.

* response_type
  * Whether the endpoint returns an authorization code. For web applications, a value of ``code`` should be used.
* client_id
  * required The client_id you obtained in the Initial Setup.
* redirect_uri
  * An HTTPS URI or custom URL scheme where the response will be redirected. Must be registered with Tidepool in the application console.
* state
  * An arbitrary string of your choosing that will be included in the response to your application. Anything that might be useful for your application can be included.

A sample GET request could therefore look like:

```
curl -X GET http://localhost:8009/auth/oauth2/authorize?client_id=d995aaabe7&response_type=code&state=secret=someStuff4Security
```

## The User Experience

Grant permissons for your application to access the users Tidepool account on your behalf

### TODO: show login form


## Response from Tidepool

```

```


# Getting the Access Token

Once your application has completed the above section and gotten an authorization code, it’ll now need to exchange the authorization code for an access token from Tidepool.

Access Token: The access token is what’s needed to sign your API requests to Tidepool.

To get the ``access_token``, you’ll need to make a ``POST`` request to http://localhost:8009/oauth/token with the following parameters:

* ``grant_type``
 * Must be authorization_code
* ``code``
 * required	The authorization code you retrieved previously
* ``client_id``
 * required	client_id gotten from Tidepool in Initial Setup
* ``client_secret``
 * required	client_secret gotten from Tidepool in Initial Setup
* ``redirect_uri``
 * required as configured from Tidepool in Initial Setup

Request: The requests must be over HTTPS and the parameters must be URL encoded.

An example request in cURL looks like:

```
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'false' http://localhost:8009/auth/oauth2/token?grant_type=authorization_code&client_id=38abd8829c&client_secret=27b1a7cd61ca4bb0a8e551d9872b62b48d397bfb&code=ApI-y_I_EeS6WNDhQIuImg
```

If everything goes right and the request is successful, you’ll receive a ``200`` response containing a JSON body like this:

```
{
    "access_token": "T9cE5asGnuyYCCqIZFoWjFHvNbvVqHjl",
    "expires_in": 3600,
    "token_type": "bearer",
    "refresh_token": "J7rxTiWOHMoSC1isKZKBZWizoRXjkQzig5C6jFgCVJ9bUnsUfGMinKBDLZWP9BgR"
}
```

# Using the Access Token

# Revoking the Access Token

