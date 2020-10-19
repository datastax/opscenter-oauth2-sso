# OpsCenter OAuth2 Authentication Strategy

```
[authentication]
# Set this option to True to enable OpsCenter authentication.  A default admin
# account will be created with the username "admin" and password "admin".
# Accounts and roles can then be created and modified from within the web UI.
enabled = True
authentication_method = com.datastax.opscenter.auth.http.impl.OAuth2Provider

[authentication_provider]
client_id = 822a7d9fce9dc503ac669f8b1b5fb787
client_secret = f03874733ded087a5a2b1557c8bfc754
authorization_url = https://www.facebook.com/v8.0/dialog/oauth
token_url = https://graph.facebook.com/v8.0/oauth/access_token
redirect_url = http://localhost:8888
scope = "openid, profile"
grant_type = client_credentials
response_type = code
```