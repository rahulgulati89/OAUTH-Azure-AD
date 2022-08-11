package com.saxobank.datahub.oauth.oauthbearer;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.util.*;

public class OAuthBearerTokenJwt implements OAuthBearerToken {

    private String accessToken;
    private long lifetimeMs;
    private String principalName;
    private long startTimeMs;
    private Set<String> scope;
    private long expirationTime;
    private String sub;

    public OAuthBearerTokenJwt(String accessToken, long lifeTimeMs, long startTimeMs, String principalName){
        this.accessToken = accessToken;
        this.principalName= principalName;
        this.lifetimeMs = startTimeMs + lifeTimeMs;
        this.startTimeMs = startTimeMs;
        this.expirationTime = startTimeMs + lifeTimeMs;
    }

    public OAuthBearerTokenJwt(String principalName, long expirationTimeMs, long startTimeMs, String subject, String accessToken){
        this.accessToken = accessToken;
        this.principalName = principalName;
        // this.expirationTime = (expiry * 1000);
        this.expirationTime = expirationTimeMs;
        // this.startTimeMs = (issue * 1000);
        this.startTimeMs = startTimeMs;
        this.lifetimeMs = expirationTime;
        this.sub = subject;
        this.scope = new TreeSet<>();
    }

    @Override
    public String value() {
        return accessToken;
    }

    @Override
    public Set<String> scope() {
        return scope;
    }

    @Override
    public long lifetimeMs() {
        return lifetimeMs;
    }

    @Override
    public String principalName() {
        return principalName;
    }

    @Override
    public Long startTimeMs() {
        return startTimeMs;
    }

    public long expirationTime(){
        return expirationTime;
    }

    public String sub(){
        return sub;
    }

    @Override
    public String toString() {
        return "OAuthBearerTokenJwt{" +
                "value='" + accessToken + '\'' +
                ", lifetimeMs=" + lifetimeMs +
                ", principalName='" + principalName + '\'' +
                ", startTimeMs=" + startTimeMs +
                ", scope=" + scope +
                ", expirationTime=" + expirationTime +
                ", sub='" + sub + '\'' +
                '}';
    }
}
