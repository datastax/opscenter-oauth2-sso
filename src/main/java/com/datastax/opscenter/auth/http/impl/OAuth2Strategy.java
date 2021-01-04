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


//TODO implement CODE_CHALLENGE
//https://www.oauth.com/oauth2-servers/pkce/
//TODO Support Google JWT validation in order to retrieve the `hd` or hosted domain attribute
//https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken
//TODO Can we support a logout endpoint?

public class OAuth2Strategy implements AuthenticationStrategy {
    private static final Logger log = LoggerFactory.getLogger(OAuth2Strategy.class);
    private final String authUrl;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final String redirect_url;
    private final String scope;
    private final Optional<String> grant_type;
    private final String response_type;
    private final String userinfo_url;
    private final String username_attribute;
    private final String role_attribute;
    private String accessToken;
    private JSONObject userInfoObj;
    private String stateString;

    public OAuth2Strategy(String client_id, String client_secret, String authorization_url,
                          String token_url, String redirect_url, String scope, Optional<String> grant_type,
                          String response_type, String userinfo_url, String username_attribute, String role_attribute) {
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
    }

    @Override
    public Identity authenticate(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws AuthenticationException, RedirectException
    {
        //For parsing responses to the OAuth server
        JSONParser jParser = new JSONParser();
        //Data for OAuth requests are largely passed in URL parameters
        Map<String,String[]> httpParams = httpServletRequest.getParameterMap();
        //Using the OkHTTP Client by Square Inc. https://square.github.io/okhttp/
        OkHttpClient okClient = new OkHttpClient().newBuilder().readTimeout(30, TimeUnit.SECONDS).build();
        //StringBuilder for building URL's when parameters are present
        StringBuilder sBuilder = new StringBuilder();

        if(httpParams.isEmpty()) {
            //Generate the state parameter to mitigate CSRF
            stateString = RandomStringUtils.randomAlphanumeric(32);
            String initialAuth =
                    sBuilder.append(authUrl)
                            .append("?response_type=").append(response_type)
                            .append("&client_id=").append(clientId)
                            .append("&redirect_uri=").append(redirect_url)
                            .append("&scope=").append(scope)
                            .append("&state=").append(stateString)
                            .toString();
            log.debug("[OAuth2Strategy] Attempted OAuth / SSO Redirect with redirect URL: " + initialAuth);
            throw new RedirectException(initialAuth);
        }
        else if (httpParams.containsKey("code") && stateString.equals(httpServletRequest.getParameter("state"))){
//            log.debug("[OAuth2Strategy] Code is "+httpServletRequest.getParameter("code"));
            StringBuilder tokenReq =
                    sBuilder.append(tokenUrl)
                            .append("?code=").append(httpServletRequest.getParameter("code"))
                            .append("&client_id=").append(clientId)
                            .append("&client_secret=").append(clientSecret)
                            .append("&redirect_uri=").append(redirect_url);
            //Append grant_type if present. Some OAuth providers do not require
            grant_type.ifPresent(s -> tokenReq.append("&grant_type=").append(s));
            String tokenReqSt = tokenReq.toString();
//            log.debug("[OAuth2Strategy] Token request URL is "+tokenReqSt);
            Request reqToken = new Request.Builder().url(tokenReqSt)
                    .method("POST",RequestBody.create("",MediaType.parse("application/x-www-form-urlencoded")))
                    .addHeader("content-type","application/x-www-form-urlencoded")
                    .addHeader("accept","application/json")
                    .build();
            Response respToken = null;
            try {
                respToken = okClient.newCall(reqToken).execute();
            }
            catch (Exception e) {
                throw new AuthenticationException("[OAuth2Strategy] An error has occurred while trying to REQUEST a bearer token"+System.lineSeparator()+e);
            }
            if(respToken.code()!=200) throw new AuthenticationException("[OAuth2Strategy] Token request unsuccessful"+System.lineSeparator()+respToken.toString());
            else {
//                log.debug("[OAuth2Strategy] Token request response is "+respToken.toString());
                try{
                    JSONObject respBody = (JSONObject) jParser.parse(Objects.requireNonNull(respToken.body()).string());
                    accessToken = respBody.get("access_token").toString();
                }
                catch(IOException | ParseException e){
                    throw new AuthenticationException("[OAuth2Strategy] An error has occurred while trying to RETRIEVE a bearer token"+System.lineSeparator()+e);
                }
                log.debug("[OAuth2Strategy] OAuth Access Token is: "+ accessToken);
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
//            log.debug("[OAuth2Strategy] UserInfo Response body is "+ userInfoObj.toString());
        }
        catch (Exception e){
            throw new AuthenticationException("[OAuth2Strategy] An error has occurred while retrieving User's Information"+System.lineSeparator()+e);
        }
        Set<String> roles = new HashSet<>();
        if (userInfoObj.containsKey(role_attribute)){
//            log.debug("[OAuth2Strategy] UserInfo contains role attribute");
//            log.debug("[OAuth2Strategy] Role attribute is "+role_attribute+" and role information is "+userInfoObj.get(role_attribute).toString());
            Object jRoles = userInfoObj.get(role_attribute);
            if (jRoles instanceof JSONArray) {
                ((JSONArray) jRoles).forEach(r -> roles.add(r.toString()));
            }
            else roles.add(jRoles.toString());
        }
        return new Identity(userInfoObj.get(username_attribute).toString(),roles);
    }
}