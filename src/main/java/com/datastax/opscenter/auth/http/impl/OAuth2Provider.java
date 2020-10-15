package com.datastax.opscenter.auth.http.impl;

import com.datastax.opscenter.auth.http.AuthenticationStrategy;
import com.datastax.opscenter.auth.http.AuthenticationStrategyProvider;
import com.datastax.opscenter.auth.http.ConfigurationException;

import java.util.Map;

public class OAuth2Provider implements AuthenticationStrategyProvider {

    @Override
    public AuthenticationStrategy build(Map<String, String> config) throws ConfigurationException {
        return new OAuth2();
    }
}
