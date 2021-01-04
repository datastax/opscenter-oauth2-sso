package com.datastax.opscenter.auth.http.impl;

import com.datastax.opscenter.auth.http.AuthenticationStrategy;
import com.datastax.opscenter.auth.http.AuthenticationStrategyProvider;
import com.datastax.opscenter.auth.http.ConfigurationException;

import java.util.Map;
import java.util.Optional;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

public class OAuth2StrategyProvider implements AuthenticationStrategyProvider {
    static String required(final Map<String, String> config, final String key, final String errorMsg) throws ConfigurationException {
        final String val = config.get(key);

        if (isNull(val)) {
            throw new ConfigurationException(
                    nonNull(errorMsg) ? errorMsg : String.format("Required key (%s) was not set.", key));
        }

        if (val.isEmpty()) {
            throw new ConfigurationException(
                    nonNull(errorMsg) ? errorMsg : String.format("Required key (%s) was an empty string value (%s)", key, val));
        }

        return val;
    }

    static String required(final Map<String, String> config, final String key) throws ConfigurationException {
        return required(config, key, null);
    }

    static Optional<String> optional(final Map<String, String> config, final String key) {
        return Optional.ofNullable(config.get(key));
    }

    public AuthenticationStrategy build(Map<String, String> config) throws ConfigurationException {
        return new OAuth2Strategy(
                required(config,"client_id"),
                required(config,"client_secret"),
                required(config,"authorization_url"),
                required(config,"token_url"),
                required(config,"redirect_url"),
                required(config,"scope"),
                optional(config,"grant_type"),
                required(config,"response_type"),
                required(config,"userinfo_url"),
                required(config,"username_attribute"),
                required(config,"role_attribute"),
                required(config,"admin_role_name")
        );
    }
}