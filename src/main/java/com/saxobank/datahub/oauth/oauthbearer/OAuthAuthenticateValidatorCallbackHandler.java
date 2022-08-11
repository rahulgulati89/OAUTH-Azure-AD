package com.saxobank.datahub.oauth.oauthbearer;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerIllegalTokenException;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerValidationResult;
import org.apache.kafka.common.utils.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class OAuthAuthenticateValidatorCallbackHandler implements AuthenticateCallbackHandler {
    private final Logger log = LoggerFactory.getLogger(OAuthAuthenticateValidatorCallbackHandler.class);
    private boolean configured = false;
    private Time time = Time.SYSTEM;

    @Override
    public void configure(Map<String, ?> map, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism)) {
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        }
        if (Objects.requireNonNull(jaasConfigEntries).size() != 1 || jaasConfigEntries.get(0) == null) {
            throw new IllegalArgumentException(
                    String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)",
                            jaasConfigEntries.size()));
        }
        configured = true;
    }

    public boolean isConfigured(){
        return this.configured;
    }

    @Override
    public void close() {
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (!isConfigured()) {
            throw new IllegalStateException("Callback handler not configured");
        }
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerValidatorCallback) {
                OAuthBearerValidatorCallback validationCallback = (OAuthBearerValidatorCallback) callback;
                try {
                    handleCallback(validationCallback);
                } catch (OAuthBearerIllegalTokenException e) {
                    OAuthBearerValidationResult failureReason = e.reason();
                    String failureScope = failureReason.failureScope();
                    validationCallback.error(failureScope != null ? "insufficient_scope" : "invalid_token",
                            failureScope, failureReason.failureOpenIdConfig());
                }
            }
            else
                throw new UnsupportedCallbackException(callback);
        }
    }

    private void handleCallback(OAuthBearerValidatorCallback callback) throws MalformedURLException, JsonProcessingException {
        String accessToken = callback.tokenValue();
        if (accessToken == null) {
            throw new IllegalArgumentException("Callback missing required token value");
        }
        log.info("Trying to introspect Token!");
        OAuthBearerTokenJwt token = OAuthImplementation.validateAADToken(accessToken);
        log.info("Token Introspection completed");

        // Implement Check Expire Token..
        long now = time.milliseconds();
        if(now > token.expirationTime()){
            throw new IllegalStateException("Expired Token, needs refresh!");
        }

        log.info("Validated! token...");
        callback.token(token);
    }

}
