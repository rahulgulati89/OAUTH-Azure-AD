package com.saxobank.datahub.oauth.oauthbearer;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.common.utils.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import java.io.IOException;

public class OAuthImplementation {

    private static final Logger log = LoggerFactory.getLogger(OAuthImplementation.class);

    private static String OAUTH_LOGIN_SERVER;
    private static String OAUTH_TENANT_ID;
    private static String OAUTH_CLIENT_ID;
    private static String OAUTH_LOGIN_AUTHORIZATION;
    private static String OAUTH_LOGIN_ENDPOINT;
    private static String OAUTH_LOGIN_GRANT_TYPE;
    private static boolean OAUTH_UNSECURE_HTTP_CONNECTION;
    private static Time time = Time.SYSTEM;

    private static void setConfigurationFromJaasConfigEntries(Map<String, String> jaasConfigEntries) {
        try {
            log.info("Trying to get properties from Sasl Jaas Config");
            Objects.requireNonNull(jaasConfigEntries);
            OAUTH_LOGIN_SERVER = (String) getConfigurationFromJaasConfiguration(jaasConfigEntries, "OAUTH_LOGIN_SERVER", "");
            OAUTH_LOGIN_ENDPOINT = (String) getConfigurationFromJaasConfiguration(jaasConfigEntries, "OAUTH_LOGIN_ENDPOINT", "");
            OAUTH_TENANT_ID = (String) getConfigurationFromJaasConfiguration(jaasConfigEntries, "OAUTH_TENANT_ID", "");
            OAUTH_LOGIN_GRANT_TYPE = (String) getConfigurationFromJaasConfiguration(jaasConfigEntries, "OAUTH_LOGIN_GRANT_TYPE", "");

            OAUTH_LOGIN_AUTHORIZATION = ((String) getConfigurationFromJaasConfiguration(
                    jaasConfigEntries, "OAUTH_AUTHORIZATION", "")).replace("%20", " ");

            OAUTH_UNSECURE_HTTP_CONNECTION = (Boolean) getConfigurationFromJaasConfiguration(jaasConfigEntries, "OAUTH_UNSECURE_HTTP_CONNECTION", false);
            OAUTH_CLIENT_ID = (String) getConfigurationFromJaasConfiguration(jaasConfigEntries, "OAUTH_CLIENT_ID", "");
        }
        catch (RuntimeException e) {
            log.warn("Error on trying to configure oauth using jaas configuration entries. Using environment configuration");
            throw e;
        }
    }

    private static Object getConfigurationFromJaasConfiguration(Map<String, String> options, String propertyName, Object defaultValue) {
        String value = options.get(propertyName) != null ? options.get(propertyName) : System.getProperty(propertyName);

        if (value == null) {
            return defaultValue;
        } else {
            if (defaultValue instanceof Boolean) {
                return Boolean.valueOf(value);
            } else if (defaultValue instanceof Integer) {
                return Integer.valueOf(value);
            } else if (defaultValue instanceof Double) {
                return Double.valueOf(value);
            } else if (defaultValue instanceof Float) {
                return Float.valueOf(value);
            } else {
                return value;
            }
        }
    }

    public static OAuthBearerTokenJwt AzureADlogin(Map<String, String> options) throws IOException {
        log.debug("Starting to request access token from OAuth server.");
        setConfigurationFromJaasConfigEntries(options);
        
        if (OAUTH_UNSECURE_HTTP_CONNECTION) {
            log.error("Connection to unsecured Authorization Server Not allowed, setting token to null");
            return null;
        }

        long currentTime = time.milliseconds();

        //Mount POST data
        String grantType = "grant_type=" + OAUTH_LOGIN_GRANT_TYPE;
        String postDataStr = grantType;

        log.info("Try to login with oauth!");
        log.info("Oauth Login Server: " + OAUTH_LOGIN_SERVER);
        log.info("Oauth Login EndPoint: " + OAUTH_LOGIN_ENDPOINT);

        Map<String, Object> resp = getTokenFromAAD(OAUTH_LOGIN_SERVER + OAUTH_TENANT_ID + OAUTH_LOGIN_ENDPOINT, postDataStr, OAUTH_LOGIN_AUTHORIZATION);

        if (resp != null) {
            String accessToken = (String) resp.get("access_token");
            long expiresIn = Long.parseLong((String) resp.get("expires_in"));
            long expireOn = (expiresIn*1000);
            log.info("OAuth Client Id in Login is " + OAUTH_CLIENT_ID);
            log.info("Expires on is " + expireOn);
            OAuthBearerTokenJwt result = new OAuthBearerTokenJwt(accessToken, expireOn, currentTime, OAUTH_CLIENT_ID);
            log.info("Token was generated");
            return result;

        } else {
            log.info("Null response from OAuth Server. Token isn't created");
            return null;
        }
    }

    public static Map<String, Object> getTokenFromAAD(String urlStr, String postParameters, String oauthToken) throws IOException {

        log.debug(String.format("Starting to make HTTP call, Url: %s.", urlStr));
        log.debug("Validate method parameters.");
        Objects.requireNonNull(urlStr);
        Objects.requireNonNull(postParameters);

        // configure SSL context to allow unsecured connections if configured
        log.debug("Configure SSL context to allow unsecured connections if configured.");
        log.debug("Send POST request, Url: {}", urlStr);
        byte[] postData = postParameters.getBytes(StandardCharsets.UTF_8);
        int postDataLength = postData.length;

        URL url = new URL("https://" + urlStr);
        log.info("URL to hit is" + url);
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("dk.proxy.mid.dom", 80));
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection(proxy);
        con.setInstanceFollowRedirects(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Authorization", oauthToken);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setRequestProperty("charset", "utf-8");
        con.setRequestProperty("Content-Length", Integer.toString(postDataLength));
        con.setUseCaches(false);
        con.setDoOutput(true);

        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            wr.write(postData);
        }

        int responseCode = con.getResponseCode();
        if (responseCode == 200) {
            log.info("Handling Token Response from Azure AD");
            return Utils.handleAADResponse(con.getInputStream());
        } else {
            // the request was not successful
            String errMsg = String.format("The request was not successful, Url: %s, Response Code: %s", urlStr, responseCode);
            log.error(errMsg);
            return null;
        }
    }

    public static OAuthBearerTokenJwt validateAADToken(String accessToken) throws MalformedURLException, JsonProcessingException {

        OAuthBearerTokenJwt result = null;
        DecodedJWT decodedJWT = null;

        log.info("Starting with Token Validation");

        String[] tokenVerification = accessToken.split("\\.");
        if (tokenVerification.length != 3) {
            throw new RuntimeException("Token does not contains 3 parts, rejecting it");
        }
        String tokenPayload = tokenVerification[1];
        log.info("Token Payload is " + tokenPayload);
        try {
            decodedJWT = JWT.decode(accessToken);
        }
        catch (IllegalArgumentException | JWTDecodeException e ) {
            log.error("Exception thrown out of token Decoding", e);
            throw new RuntimeException(e);
        }

        log.info("Trying to match token signing keys with Azure AD keys");
        JwkProvider provider = new UrlJwkProvider(new URL("https://login.microsoftonline.com/common/discovery/keys"));
        try {
            Jwk jwk = provider.get(decodedJWT.getKeyId());
            log.info("Jwk key is, JWKKey: {}", jwk.getId());
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            algorithm.verify(decodedJWT);
            log.info("Token signing is correct");
        }
        catch (NullPointerException | JwkException | SignatureVerificationException e) {
            log.error("Token Signing, Verification thrown Exception", e);
            throw new RuntimeException(e);
        }
        log.info("Decoding the token using Base 64");
        Base64.Decoder decoder = Base64.getDecoder();
        String accessTokenPayloadDecoded = new String(decoder.decode(tokenPayload));

        log.info("Decoded Token payload is " + accessTokenPayloadDecoded);

        ObjectMapper mapper = new ObjectMapper();
        Map<String,Object> map = mapper.readValue(accessTokenPayloadDecoded, Map.class);
        log.info("Map is " + map);
        String clientid = (String) map.get("appid");
        long exptime = decodedJWT.getExpiresAt().getTime();
        long isstime = decodedJWT.getIssuedAt().getTime();
        String subject = decodedJWT.getSubject();

        log.info("Token expiration time is " + exptime);
        log.info("Token start time is "+ isstime);
        log.info("Token client id is " + clientid);

        return new OAuthBearerTokenJwt(clientid, exptime, isstime, subject, accessToken);
    }
}

