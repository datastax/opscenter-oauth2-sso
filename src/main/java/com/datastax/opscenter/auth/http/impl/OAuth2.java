package com.datastax.opscenter.auth.http.impl;

import com.datastax.opscenter.auth.http.AuthenticationException;
import com.datastax.opscenter.auth.http.AuthenticationStrategy;
import com.datastax.opscenter.auth.http.Identity;
import com.datastax.opscenter.auth.http.RedirectException;
import org.dmfs.httpessentials.client.HttpRequestExecutor;
import org.dmfs.httpessentials.exceptions.ProtocolError;
import org.dmfs.httpessentials.exceptions.ProtocolException;
import org.dmfs.httpessentials.httpurlconnection.HttpUrlConnectionExecutor;
import org.dmfs.oauth2.client.*;
import org.dmfs.oauth2.client.grants.ImplicitGrant;
import org.dmfs.oauth2.client.scope.BasicScope;
import org.dmfs.rfc3986.encoding.Precoded;
import org.dmfs.rfc3986.uris.LazyUri;
import org.dmfs.rfc5545.Duration;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class OAuth2 implements AuthenticationStrategy {
    private final String authUrl;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final String redirect_url;
    private final String scope;
    private final String grant_type;
    private final String response_type;

    public OAuth2(String client_id, String client_secret, String authorization_url,
                        String token_url, String redirect_url, String scope, String grant_type,
                        String response_type) {
        this.authUrl        = authorization_url;
        this.tokenUrl       = token_url;
        this.clientId       = client_id;
        this.clientSecret   = client_secret;
        this.redirect_url   = redirect_url;
        this.scope          = scope;
        this.grant_type     = grant_type;
        this.response_type  = response_type;
    }

    @Override
    public Identity authenticate(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, RedirectException {
        Map<String,String[]> httpParams = httpServletRequest.getParameterMap();
        System.out.println("~~~~~~~ Here is where the authenticate method gets called. ~~~~~~~");
        Set<String> roles = new HashSet<>();
        roles.add("admin");
        HttpRequestExecutor executor = new HttpUrlConnectionExecutor();
        OAuth2AuthorizationProvider provider = new BasicOAuth2AuthorizationProvider(
            URI.create(authUrl),//auth endpoint
            URI.create(tokenUrl),//token endpoint
            new Duration(1,0,3600)
        );
        OAuth2ClientCredentials credentials = new BasicOAuth2ClientCredentials(
                clientId, clientSecret);
        OAuth2Client client = new BasicOAuth2Client(
            provider,
            credentials,
            new LazyUri(new Precoded(redirect_url))
        );
        System.out.println("~~~~~~~ grant_type is " + grant_type + " ~~~~~~~");
        System.out.println("~~~~~~~ response_type is " + response_type + " ~~~~~~~");
        OAuth2InteractiveGrant grant = new ImplicitGrant(client, new BasicScope(scope));
        URI authorizationUrl = grant.authorizationUrl();
        if(httpParams.isEmpty()) {
            try {
                System.out.println("~~~~~~~ auth_url is " + authorizationUrl.toString() + " ~~~~~~~");
                throw new RedirectException(authorizationUrl.toString());
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }
        else {
            try {
                OAuth2AccessToken token = grant.withRedirect(client.redirectUri()).accessToken(executor);
                System.out.println("~~~~~~~ Here is the access token: " + token.toString() + " ~~~~~~~");
            } catch (IOException | ProtocolError | ProtocolException e) {
                e.printStackTrace();
            }
        }

        /*
            Ideally, you would use the returned values from the token and subsequent information
            to fill in the display name and roles for the Identity object.
        */
        return new Identity("admin",roles);
    }
}
