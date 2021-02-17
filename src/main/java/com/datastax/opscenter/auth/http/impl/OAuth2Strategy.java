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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    private final String use_base64_token_req;
    private String accessToken;
    private JSONObject userInfoObj;
    private String stateString;

    public OAuth2Strategy(String client_id, String client_secret, String authorization_url, String token_url, String redirect_url,
                          String scope, String grant_type, String response_type, String userinfo_url, String username_attribute,
                          String role_attribute, String admin_role_name, String use_base64_token_req) {
        this.authUrl                = authorization_url;
        this.tokenUrl               = token_url;
        this.clientId               = client_id;
        this.clientSecret           = client_secret;
        this.redirect_url           = redirect_url;
        this.scope                  = scope;
        this.grant_type             = grant_type;
        this.response_type          = response_type;
        this.userinfo_url           = userinfo_url;
        this.username_attribute     = username_attribute;
        this.role_attribute         = role_attribute;
        this.admin_role_name        = admin_role_name;
        this.use_base64_token_req   = use_base64_token_req;
    }

    private void getAuthenticationCode() throws RedirectException {
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
        log.debug("[OAuth2Strategy] Attempted OAuth / SSO Redirect with redirect URL: " + initialAuth);
        throw new RedirectException(initialAuth);
    }

    private Request getAccessTokenRequestBase64(HttpServletRequest httpServletRequest) {
        HttpUrl tokenEndpoint = HttpUrl.get(tokenUrl);
        String tokenReqSt = tokenEndpoint.newBuilder()
                .addQueryParameter("code",httpServletRequest.getParameter("code"))
                .addQueryParameter("redirect_uri",redirect_url)
                .addQueryParameter("grant_type",grant_type)
                .build().toString();
        log.debug("[OAuth2Strategy] Token request URL is "+tokenReqSt);
        String clientIdAndSecret = clientId+":"+clientSecret;
        return
            new Request.Builder().url(tokenReqSt)
                .method("POST",RequestBody.create("",MediaType.parse("application/x-www-form-urlencoded")))
                .addHeader("Authorization","Basic "+Base64.getEncoder().encodeToString(clientIdAndSecret.getBytes()))
                .addHeader("content-type","application/x-www-form-urlencoded")
                .addHeader("accept","application/json")
                .build();
    }

    private Request getAccessTokenRequest(HttpServletRequest httpServletRequest) {
        HttpUrl tokenEndpoint = HttpUrl.get(tokenUrl);
        String tokenReqSt = tokenEndpoint.newBuilder()
                .addQueryParameter("code",httpServletRequest.getParameter("code"))
                .addQueryParameter("redirect_uri",redirect_url)
                .addQueryParameter("client_id",clientId)
                .addQueryParameter("client_secret",clientSecret)
                .addQueryParameter("grant_type",grant_type)
                .build().toString();
        log.debug("[OAuth2Strategy] Token request URL is "+tokenReqSt);
        return
            new Request.Builder().url(tokenReqSt)
                .method("POST",RequestBody.create("",MediaType.parse("application/x-www-form-urlencoded")))
                .addHeader("content-type","application/x-www-form-urlencoded")
                .addHeader("accept","application/json")
                .build();
    }

    private Request getUserInfoRequest(){
        return new Request.Builder().url(userinfo_url)
            .method("GET", null)
            .addHeader("Authorization", "Bearer " + accessToken)
            .addHeader("Content-Type", "application/json")
            .build();
    }

    private void getAccessToken(Request requestToken, OkHttpClient okClient, JSONParser jParser) throws AuthenticationException {
        Response respToken = null;
        try {
            respToken = okClient.newCall(requestToken).execute();
            log.debug("[OAuth2Strategy] Token request response is " + respToken.toString());
        } catch (Exception e) {
            throw new AuthenticationException("[OAuth2Strategy] An error has occurred while trying to REQUEST an access token"+System.lineSeparator()+e);
        }
        if(respToken.code()==200){
            try {
                JSONObject respBody = (JSONObject) jParser.parse(Objects.requireNonNull(respToken.body()).string());
                accessToken = respBody.get("access_token").toString();
                log.debug("[OAuth2Strategy] OAuth Access Token is: "+ accessToken);
            } catch(Exception e) {
                throw new AuthenticationException(
                    "[OAuth2Strategy] An error has occurred while trying to RETRIEVE a bearer token from the response"+System.lineSeparator()+e
                );
            }
        }
        else throw new AuthenticationException("[OAuth2Strategy] Access Token request unsuccessful"+System.lineSeparator()+respToken.toString());
    }

    private JSONObject getUserInfo(Request userInfoReq, OkHttpClient okClient, JSONParser jParser) throws AuthenticationException {
        JSONObject userInfoObject;
        try {
            Response response = okClient.newCall(userInfoReq).execute();
            userInfoObject = (JSONObject) jParser.parse(Objects.requireNonNull(response.body()).string());
            log.debug("[OAuth2Strategy] User Info request response is "+response.toString());
            log.debug("[OAuth2Strategy] User Info response body is "+userInfoObject.toString());
        }
        catch (Exception e){
            throw new AuthenticationException("[OAuth2Strategy] An error has occurred while retrieving User's Information"+System.lineSeparator()+e);
        }
        return userInfoObject;
    }

    private Set<String> getRolesFromUserInfo(JSONObject jObj) {
        Object jRoles = jObj.get(role_attribute);
        Set<String> rolesSet = new HashSet<>();
        log.debug("[OAuth2Strategy] Role attribute is "+role_attribute+" and role information is "+jObj.get(role_attribute).toString());
        if (jRoles instanceof JSONArray) {
            ((JSONArray) jRoles).forEach(r -> {
                    //Check to see if the supplied role attribute array matches the Admin role
                    if (r.toString().equals(admin_role_name)){
                        rolesSet.add("admin");
                    }
                    else rolesSet.add(r.toString());
                }
            );
        }
        //Check to see if the supplied role attribute matches the Admin role
        else if (jRoles.toString().equals(admin_role_name)) rolesSet.add("admin");
        else rolesSet.add(jRoles.toString());
        return rolesSet;
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
        //Use UserInfo response to build OpsCenter role
        Set<String> roles;

        //This should be the initial login request, no URL parameters
        if(urlParams.isEmpty()) {
            getAuthenticationCode();
        }
        //After receiving a code, request access token
        else if (urlParams.containsKey("code") && stateString.equals(httpServletRequest.getParameter("state"))){
            Request tokenRequest = null;
            if(use_base64_token_req.equalsIgnoreCase("true")){
                tokenRequest = getAccessTokenRequestBase64(httpServletRequest);
            } else {
                tokenRequest = getAccessTokenRequest(httpServletRequest);
            }
            getAccessToken(tokenRequest,okClient,jParser);
        }
        else throw new AuthenticationException("[OAuth2Strategy] There has been a problem retrieving OAuth authentication or authorization");

        //Begin process to get the authenticated user's information
        Request userInfoRequest = getUserInfoRequest();
        userInfoObj = getUserInfo(userInfoRequest,okClient,jParser);
        if (userInfoObj.containsKey(role_attribute)){
            log.debug("[OAuth2Strategy] UserInfo contains role attribute");
            roles = getRolesFromUserInfo(userInfoObj);
        }
        else throw new AuthenticationException("[OAuth2Strategy] No role attribute was found");

        return new Identity(userInfoObj.get(username_attribute).toString(),roles);
    }
}