package com.datastax.opscenter.auth.http.impl;

import com.datastax.opscenter.auth.http.AuthenticationException;
import com.datastax.opscenter.auth.http.AuthenticationStrategy;
import com.datastax.opscenter.auth.http.Identity;
import com.datastax.opscenter.auth.http.RedirectException;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class OAuth2 implements AuthenticationStrategy {

    @Override
    public Identity authenticate(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, RedirectException {
        Config config = ConfigFactory.load();
        Map<String,String[]> httpParams = httpServletRequest.getParameterMap();
        System.out.println("look ma I made it");
        Set<String> roles = new HashSet<>();
        roles.add("admin");
//        if (httpParams.isEmpty()) {
//            try {
//                throw new RedirectException(
//                    config.getString("login_url") + "?" +
//                        "redirect_uri=" + config.getString("opscenter_url") + "&" +
//                        "scope=openid profile" + "&" +
//                        "response_type=code" + "&" +
//                        "client_id=" + config.getString("client_id")
//
//                );
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//            return null;
//        } else if (httpParams.containsKey(config.getString("auth_code_param"))) {
//            try {
//                httpServletResponse.sendRedirect(
//            config.getString("token_url") + "?" +
//                        "client_id=" + config.getString("client_id") + "&" +
//                        "client_secret=" + config.getString("client_secret") + "&" +
//                        "grant_type=authorization_code" + "&" +
//                        "code=" + httpParams.get(config.getString("auth_code_param"))[0] + "&" +
//                        "scope=openid profile" + "&" +
//                        "redirect_uri=" + config.getString("opscenter_url")
//                );
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }
        return new Identity("admin",roles);
    }
}
