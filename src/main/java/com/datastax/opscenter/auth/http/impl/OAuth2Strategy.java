package com.datastax.opscenter.auth.http.impl;

import com.datastax.opscenter.auth.http.AuthenticationException;
import com.datastax.opscenter.auth.http.AuthenticationStrategy;
import com.datastax.opscenter.auth.http.Identity;
import com.datastax.opscenter.auth.http.RedirectException;
import okhttp3.*;
import org.apache.commons.lang.RandomStringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

//https://www.oauth.com/oauth2-servers/pkce/
//TODO implement CODE_CHALLENGE
//TODO Can we support a logout endpoint?

public class OAuth2Strategy implements AuthenticationStrategy {
    private static final Logger log = LoggerFactory.getLogger(OAuth2Strategy.class);
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
    private final String role_attribute;
    private final String admin_role_name;
    private String accessToken;
    private JSONObject userInfoObj;
    private String stateString;

    public OAuth2Strategy(String client_id, String client_secret, String authorization_url, String token_url, String redirect_url,
                          String scope, String grant_type, String response_type, String userinfo_url, String username_attribute,
                          String role_attribute, String admin_role_name) {
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
        this.role_attribute     = role_attribute;
        this.admin_role_name    = admin_role_name;
    }

    @Override
    public Identity authenticate(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws AuthenticationException, RedirectException
    {
        //For parsing responses to the OAuth server
        JSONParser jParser = new JSONParser();
        //Data for OAuth requests are largely passed in URL parameters
        Map<String,String[]> urlParams = httpServletRequest.getParameterMap();
        //Using the OkHTTP Client by Square Inc. https://square.github.io/okhttp/
        OkHttpClient okClient = new OkHttpClient().newBuilder().readTimeout(30, TimeUnit.SECONDS).build();
        //StringBuilder for building URL's when parameters are present
        StringBuilder sBuilder = new StringBuilder();
        //This should be the initial login request, no URL parameters
        if(urlParams.isEmpty()) {
            //Generate the state parameter to mitigate CSRF
            //https://auth0.com/docs/protocols/state-parameters
            stateString = RandomStringUtils.randomAlphanumeric(32);
            HttpUrl authEndpoint = HttpUrl.get(authUrl);
            String initialAuth = authEndpoint.newBuilder()
                    .addQueryParameter("response_type",response_type)
                    .addQueryParameter("client_id",clientId)
                    .addQueryParameter("redirect_uri",redirect_url)
                    .addQueryParameter("scope",scope)
                    .addQueryParameter("state",stateString)
                    .build().toString();
            //Initial redirect to OAuth2 provider authentication endpoint
            log.info("[OAuth2Strategy] Attempted OAuth / SSO Redirect with redirect URL: " + initialAuth);
            throw new RedirectException(initialAuth);
        }
        else if (urlParams.containsKey("code") && stateString.equals(httpServletRequest.getParameter("state"))){
            HttpUrl tokenEndpoint = HttpUrl.get(tokenUrl);
            String tokenReqSt = tokenEndpoint.newBuilder()
                    .addQueryParameter("code",httpServletRequest.getParameter("code"))
                    .addQueryParameter("client_id",clientId)
                    .addQueryParameter("client_secret",clientSecret)
                    .addQueryParameter("redirect_uri",redirect_url)
                    .addQueryParameter("grant_type",grant_type)
                    .build().toString();
            log.info("[OAuth2Strategy] Token request URL is "+tokenReqSt);
            Request reqToken = new Request.Builder().url(tokenReqSt)
                    .method("POST",RequestBody.create("",MediaType.parse("application/x-www-form-urlencoded")))
                    .addHeader("content-type","application/x-www-form-urlencoded")
                    .addHeader("accept","application/json")
                    .build();
            Response respToken = null;
            try {
                respToken = okClient.newCall(reqToken).execute();
                log.info("[OAuth2Strategy] Token request response is "+respToken.toString());
                if(respToken.code()==200){
                    try{
                        JSONObject respBody = (JSONObject) jParser.parse(Objects.requireNonNull(respToken.body()).string());
                        accessToken = respBody.get("access_token").toString();
                        log.info("[OAuth2Strategy] OAuth Access Token is: "+ accessToken);
                    }
                    catch(IOException | ParseException e){
                        throw new AuthenticationException(
                            "[OAuth2Strategy] An error has occurred while trying to RETRIEVE a bearer token from the response"+System.lineSeparator()+e
                        );
                    }
                }
                else throw new AuthenticationException("[OAuth2Strategy] Token request unsuccessful"+System.lineSeparator()+respToken.toString());
            }
            catch (Exception e) {
                throw new AuthenticationException("[OAuth2Strategy] An error has occurred while trying to REQUEST a bearer token"+System.lineSeparator()+e);
            }
        }
        else throw new AuthenticationException("[OAuth2Strategy] There has been a problem retrieving OAuth authentication or authorization");
        //Build UserInfo Authenticated Request
        Request userInfo = new Request.Builder().url(userinfo_url)
                .method("GET", null)
                .addHeader("Authorization", "Bearer " + accessToken)
                .addHeader("Content-Type", "application/json")
                .build();
        try {
            Response response = okClient.newCall(userInfo).execute();
            userInfoObj = (JSONObject) jParser.parse(Objects.requireNonNull(response.body()).string());
        }
        catch (Exception e){
            throw new AuthenticationException("[OAuth2Strategy] An error has occurred while retrieving User's Information"+System.lineSeparator()+e);
        }
        //Use UserInfo response to build OpsCenter role
        Set<String> roles = new HashSet<>();
        if (userInfoObj.containsKey(role_attribute)){
            log.info("[OAuth2Strategy] UserInfo contains role attribute");
            Object jRoles = userInfoObj.get(role_attribute);
            log.info("[OAuth2Strategy] Role attribute is "+role_attribute+" and role information is "+userInfoObj.get(role_attribute).toString());
            log.info("[OAuth2Strategy] UserInfo Response body is "+ userInfoObj.toString());
            if (jRoles instanceof JSONArray) {
                ((JSONArray) jRoles).forEach(r -> {
                    //Check to see if the supplied role attribute array matches the Admin role
                    if (r.toString().equals(admin_role_name)){
                        roles.add("admin");
                    }
                    else roles.add(r.toString());
                    }
                );
            }
            //Check to see if the supplied role attribute matches the Admin role
            else if (jRoles.toString().equals(admin_role_name)) roles.add("admin");
            else roles.add(jRoles.toString());
        }
        else throw new AuthenticationException("[OAuth2Strategy] No role attribute was found");
        return new Identity(userInfoObj.get(username_attribute).toString(),roles);
    }
}