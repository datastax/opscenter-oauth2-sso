package com.datastax.capitalone.auth.http.impl;

import com.datastax.opscenter.auth.http.AuthenticationException;
import com.datastax.opscenter.auth.http.AuthenticationStrategy;
import com.datastax.opscenter.auth.http.Identity;
import com.datastax.opscenter.auth.http.RedirectException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import okhttp3.*;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class OAuth2 implements AuthenticationStrategy {
    private static final Logger log = LoggerFactory.getLogger(OAuth2.class);
    private final String authUrl;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final String redirect_url;
    private final String scope;
    private final String grant_type;
    private final String response_type;
    private final String userinfo_url;
    private final String username_attribute;
    private String accessToken;
    private JSONObject userInfoObj;
    private String stateString;

    public OAuth2(String client_id, String client_secret, String authorization_url,
                          String token_url, String redirect_url, String scope, String grant_type,
                          String response_type, String userinfo_url, String username_attribute) {
        this.authUrl            = authorization_url;
        this.tokenUrl           = token_url;
        this.clientId           = client_id;
        this.clientSecret       = client_secret;
        this.redirect_url       = redirect_url;
        this.scope              = scope;
        this.grant_type         = grant_type;
        this.response_type      = response_type;
        this.userinfo_url       = userinfo_url;
        this.username_attribute = username_attribute;
    }

    @Override
    public Identity authenticate(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws AuthenticationException, RedirectException
    {
        JSONParser jParser = new JSONParser();
        Map<String,String[]> httpParams = httpServletRequest.getParameterMap();
        Set<String> roles = new HashSet<>();    //TODO Remove after token request is complete
        roles.add("admin");                     //TODO Remove after token request is complete

        //Using the OkHTTP Client by Square Inc. https://square.github.io/okhttp/
        OkHttpClient okClient = new OkHttpClient().newBuilder().readTimeout(30, TimeUnit.SECONDS).build();

        if(httpParams.isEmpty()) {
            //Generate the state parameter to mitigate CSRF
            stateString = RandomStringUtils.randomAlphanumeric(32);
            String initialAuth = authUrl +
                    "?response_type=" + response_type +
                    "&client_id=" + clientId +
                    "&redirect_uri=" + redirect_url +
                    "&scope=" + scope +
                    "&state=" + stateString;
            log.debug("[OAuth2Strategy] Attempted OAuth / SSO Redirect with redirect URL: " + initialAuth);
            throw new RedirectException(initialAuth);
        }
        else if (httpParams.containsKey("code") && stateString.equals(httpServletRequest.getParameter("state"))){
            try {
                Request reqToken = new Request.Builder().url(
                        tokenUrl+
                                "?code="+httpServletRequest.getParameter("code")+
                                "&grant_type="+grant_type+
                                "&client_id="+clientId+
                                "&client_secret="+clientSecret+
                                "&redirect_uri="+redirect_url
                )
                        .addHeader("content-type","application/x-www-form-urlencoded")
                        .addHeader("accept","application/json")
                        .build();
                Response respToken = okClient.newCall(reqToken).execute();
                JSONObject respBody = (JSONObject) jParser.parse(Objects.requireNonNull(respToken.body()).string());
                log.debug("[OAuth2Strategy] Token request response is "+respToken.toString());
                accessToken = respBody.get("access_token").toString();
                log.debug("[OAuth2Strategy] OAuth Access Token is: "+accessToken);
            }
            catch (Exception e) {e.printStackTrace();}
        }
        else throw new AuthenticationException("There has been a problem retrieving OAuth authentication or authorization");
        try {
            Request userInfo = new Request.Builder().url(userinfo_url)
                    .method("GET", null)
                    .addHeader("Authorization", "Bearer " + accessToken)
                    .addHeader("Content-Type", "application/json")
                    .build();
            Response response = okClient.newCall(userInfo).execute();
            userInfoObj = (JSONObject) jParser.parse(Objects.requireNonNull(response.body()).string());
            log.debug("[OAuth2Strategy] UserInfo Response body is "+userInfoObj.toString());
        }
        catch (Exception e){System.out.println(e);}

        return new Identity(userInfoObj.get(username_attribute).toString(),roles); //TODO find common OAuth profile attribute for a role, or define config
    }
}
