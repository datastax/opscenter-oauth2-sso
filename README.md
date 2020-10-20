# OpsCenter OAuth2 Authentication Strategy
## Enabling pluggable auth in OpsCenter
See [this link](https://docs.datastax.com/en/opscenter/6.8/opsc/configure/opscEnablingAuth.html) for information on enabling 
pluggable auth in OpsCenter.
## Auth Directories
The below directories contain the authentication framework SDK jar and API documentation.
- File names
    - API Docs: `opscenter-auth-docs-opscenter_version.tgz`
    - SDK Jar: `opscenter-auth-api-opscenter_version.jar`
- Tarball Install
    - `install_location/opscenter/auth`
- Package Install
    - `usr/share/opscenter/auth`
### SDK Dependency
The OpsCenter Auth API should be placed into the project's imported libraries, or installed into the local dependency library. In Maven, this is 
accomplished by running the following command (the example is based on a package install):
```bash
mvn install:install-file \
      -Dfile=/usr/share/opscenter/auth/opscenter-auth-api-6.7.8.jar \
      -DgroupId=com.datastax.opscenter.auth \
      -DartifactId=http \
      -Dversion=6.7.8 \
      -Dpackaging=jar \
      -DgeneratePom=true
```
## Building The Auth Jar
Ensure that the jar is compiled with all dependencies (UberJar) and is placed in the OpsCenter classpath noted below.
Also, a file denoting the location of the auth class must be located in a specific directory within the compiled jar.
- The specific directory is `META-INF/services/` and the name of the file must be `com.datastax.opscenter.auth.http.AuthenticationStrategyProvider`.
    - In Maven, this is accomplished by including the directories and file in the `./src/main/resources` directory.
- The contents of the file must be the fully qualified package name of your Auth _Provider_ class.
    - e.g. `com.datastax.opscenter.auth.http.impl.OAuth2Provider` 
### Classpath Location
After building the auth jar, place it in OpsCenter's classpath. All of the required jars for OpsCenter will be in this directory.
- Tarball Install
    - `install_location/opscenter/lib/jvm`
- Package Install
    - `etc/opscenter/lib/jvm`
## Configuration File Updates
Ensure in the `[authentication]` section that `enabled = True` and `authentication_method = com.datastax.opscenter.auth.http.impl.OAuth2Provider`.
Add the `[authentication_provider]` section with the below configuration keys. Adding additional keys can be accomplished by modifying the `build`
method in the OAuth2Provider class and the OAuth2 constructor in the OAuth2 class. 
```
[authentication]
# Set this option to True to enable OpsCenter authentication.  A default admin
# account will be created with the username "admin" and password "admin".
# Accounts and roles can then be created and modified from within the web UI.
enabled = True
authentication_method = com.datastax.opscenter.auth.http.impl.OAuth2Provider

[authentication_provider]
client_id = id
client_secret = SuperSecret
authorization_url = authorization.oauth2
token_url = token.oauth2
redirect_url = opscenter.url
scope = "openid, profile"
grant_type = client_credentials
response_type = code
```
### Multiple Authentication Strategy
See [this link](https://docs.datastax.com/en/opscenter/6.8/opsc/configure/opscPluggableAuth.html) for examples on chaining strategies within OpsCenter.
This will allow you to use both OAuth2 and LDAP if required.
