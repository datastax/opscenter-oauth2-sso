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
## SDK Dependency
The OpsCenter Auth API should be placed into the project's imported libraries, or installed into the local dependency library.
In Maven, installing in the local library is accomplished by running the following command:
```bash
mvn install:install-file \
      -Dfile=/path/to/opscenter/auth/jar/opscenter-auth-api-6.7.8.jar \
      -DgroupId=com.datastax.opscenter.auth \
      -DartifactId=http \
      -Dversion=6.7.8 \
      -Dpackaging=jar \
      -DgeneratePom=true
```
## Building The Auth Jar
Ensure that the jar is compiled with all dependencies (UberJar) by running `mvn package` and is placed in the OpsCenter classpath noted below.
Also, a file denoting the location of the auth class must be located in a specific directory within the compiled jar.
- The specific directory is `META-INF/services/` and the name of the file must be `com.datastax.opscenter.auth.http.AuthenticationStrategyProvider`.
    - In Maven, this is accomplished by including the directories and file in the `./src/main/resources` directory.
- The contents of the file must be the fully qualified package name of your Auth _Provider_ class.
    - e.g. `com.datastax.opscenter.auth.http.impl.OAuth2StrategyProvider`
This will be automatically accomplished by running `mvn package`.
## Classpath Location
After building the auth jar, place it in OpsCenter's classpath. All the required jars for OpsCenter will be in this directory, 
so if you find a directory with a lot of jar files you're probably in the right place.
Locations for the OpsCenter classpath may vary by installation, but can generally be found in the following locations: 
- Tarball Install
    - `install_location/opscenter/lib/jvm`
- Package Install
    - `etc/opscenter/lib/jvm`
    - `usr/share/opscenter/lib/jvm`
## Configuration File Updates
Ensure in the `[authentication]` section that `enabled = True` and `authentication_method = com.datastax.opscenter.auth.http.impl.OAuth2StrategyProvider`.
Add the `[authentication_provider]` section with the below configuration keys. Adding additional keys can be accomplished by modifying the `build`
method in the `OAuth2StrategyProvider` class and the OAuth2 constructor in the `OAuth2Strategy` class. In order to achieve a user's login with admin-level permissions,
ensure `admin_role_name` matches the value within `role_attribute`.
The below methodology will allow you to login to OpsCenter with a test GitHub application.  
```
[authentication]
# Set this option to True to enable OpsCenter authentication.  A default admin
# account will be created with the username "admin" and password "admin".
# Accounts and roles can then be created and modified from within the web UI.
enabled = True
authentication_method = com.datastax.opscenter.auth.http.impl.OAuth2StrategyProvider

[authentication_provider]
client_id = 13ec4fdd5a8affc81e31
client_secret = e843ffaefc7330a574e2f3dd04c8b16d0661eab2
authorization_url = https://github.com/login/oauth/authorize
token_url = https://github.com/login/oauth/access_token
userinfo_url = https://api.github.com/user
redirect_url = http://localhost:8888/login
scope = repo gist
grant_type = authorization_code
response_type = code
username_attribute = name
role_attribute = type
admin_role_name = User
use_base64_token_request = true
```
