# OAuth Azure AD
  
- [Brief](#brief)
- [How to use](#how-to-use)

## Brief

The OAuthbearer Azure AD tool is developed to extend Confluent default unsecure OAuth implementation to a secure one involving Azure Active Directory as an Authorization server. To make the default implementation secure, this involves requesting the OAuth JWT(JSON Web Token) token from Azure AD based on client credentials grant type and Validates the token using auth0 JWT Token Decoding library. This is then integrated with Confluent Login & Validation Callback handlers to ensure that this can be used in confluent platform. This tool is intended to be used with Confluent platform and jars should be available during Confluent platform deployment.


## How to use

A new pipeline has already been created to build this and artifact for this tool is available on our JFrog Artifactory [here](https://artifacts.sys.dom/artifactory/maven-local/com/saxobank/datahub/oauth/).

This artifact jar along with 2 other dependencies(`java-jwt` & `jwks-rsa`) are required to be used by different components of the Confluent platform i.e. Brokers, SR, C3, Connect for this OAuth Azure AD integration. Each component of the platform requires the jar files to be at a specific location:

1. Brokers -> `/usr/share/java/kafka`
2. Connect -> `/usr/share/java/kafka`
3. C3 -> `/usr/share/java/confluent-control-center`
4. SR -> `/usr/share/java/schema-registry`

To connect .Net/Java clients to OAuth Azure AD backed cluster, some parameters need to be passed through Producer/Consumer client Sasl Jaas config. Parameters and their sample values are mentioned below.

- OAUTH_LOGIN_SERVER="login.microsoftonline.com/" 
- OAUTH_LOGIN_ENDPOINT="/oauth2/token" 
- OAUTH_LOGIN_GRANT_TYPE=client_credentials
- OAUTH_AUTHORIZATION="Basic $ENCODED_AZURE_AD_APP_CLIENT_ID_CLIENT_SECRET" 
- OAUTH_CLIENT_ID="$AZURE_AD_APP_CLIENT_ID" 
- OAUTH_ACCEPT_UNSECURE_SERVER=false

For instance, a Kafka Producer/Consumer connecting to OAuth Azure AD cluster and trying to produce/consume data needs to specify producer/consumer configs like below.

```
security.protocol=SASL_PLAINTEXT
sasl.mechanism=OAUTHBEARER
sasl.login.callback.handler.class=com.saxobank.rgul.oauth.oauthbearer.OAuthAuthenticateLoginCallbackHandler
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required OAUTH_LOGIN_SERVER="login.microsoftonline.com/"  OAUTH_LOGIN_ENDPOINT="/oauth2/token" OAUTH_LOGIN_GRANT_TYPE=client_credentials OAUTH_AUTHORIZATION="Basic *****" OAUTH_TENANT_ID="12345" OAUTH_CLIENT_ID="12345"
OAUTH_ACCEPT_UNSECURE_SERVER=false
```

This would then go on to request an access token from Azure AD based on the client credentials passed in the sasl jaas config and kafka broker will validate that token based different token parameters like token header/payload/signature, token algorithm & token expiry. Upon successful validation of Azure AD token, client(producer/consumer) will be authenticated for producing and consuming data to the topic.

Upon successful Authentication, following entries should appear in broker logs.

```
INFO Retrieved token.. (com.saxobank.datahub.oauth.oauthbearer.OAuthAuthenticateLoginCallbackHandler)
[2020-09-03 14:01:34,886] INFO Successfully logged in. (org.apache.kafka.common.security.oauthbearer.internals.expiring.ExpiringCredentialRefreshingLogin)
```

Note that once the authentication is passed, client id of the Azure AD application also need to be granted appropriate Read/Write ACL's to produce or consume data. These permissions need to be requested in the similar way as it is being done now using Topic definition file.