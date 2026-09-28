/*
 * Copyright 2017-2023 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.annotation.EachProperty;
import io.micronaut.context.annotation.Parameter;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

import java.time.Duration;

/**
 * JSON Web Key Set (JWKS) Signature Configuration properties holder.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@EachProperty(JwksSignatureConfigurationProperties.PREFIX)
public class JwksSignatureConfigurationProperties implements JwksSignatureConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".signatures.jwks";

    /**
     * The default key type.
     */
    @SuppressWarnings("WeakerAccess")
    public static final KeyType DEFAULT_KEYTYPE = KeyType.RSA;

    /**
     * The default cache expiration.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int DEFAULT_CACHE_EXPIRATION = 60;

    /**
     * The default number of retries when fetching the JSON Web Key Set.
     */
    @SuppressWarnings("WeakerAccess")
    public static final int DEFAULT_RETRY_ATTEMPTS = 0;

    /**
     * The default value for serving the last successfully fetched JSON Web Key Set when fetching fails.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_SERVE_STALE_ON_FAILURE = false;

    @Nullable
    private final String name;

    @NonNull
    private Integer cacheExpiration = DEFAULT_CACHE_EXPIRATION;

    private String url;

    private KeyType keyType = DEFAULT_KEYTYPE;

    private int retryAttempts = DEFAULT_RETRY_ATTEMPTS;

    @NonNull
    private Duration retryDelay = Duration.ZERO;

    private boolean serveStaleOnFailure = DEFAULT_SERVE_STALE_ON_FAILURE;

    @Nullable
    private Duration staleMaxAge;
    
    public JwksSignatureConfigurationProperties(@Parameter String name) {
        this.name = name;
    }

    @Override
    @NonNull
    public String getName() {
        return name;
    }

    /**
     * @deprecated Not used. JWKS is cached via Micronaut Cache. You need an implementation of Micronaut Cache and the cache configuration micronaut.caches.jwks.expire-after-write
     * @return The number of seconds to cache the JWKS.
     */
    @Override
    @NonNull
    @Deprecated(forRemoval = true, since = "4.11.0")
    public Integer getCacheExpiration() {
        return cacheExpiration;
    }

    /**
     * JWKS cache expiration. Default value {@value #DEFAULT_CACHE_EXPIRATION} seconds.
     * @param cacheExpiration The expiration
     * @deprecated Not used. JWKS is cached via Micronaut Cache. You need an implementation of Micronaut Cache and the cache configuration micronaut.caches.jwks.expire-after-write
     */
    @Deprecated(forRemoval = true, since = "4.11.0")
    public void setCacheExpiration(Integer cacheExpiration) {
        ArgumentUtils.requireNonNull("cacheExpiration", cacheExpiration);
        this.cacheExpiration = cacheExpiration;
    }

    /**
     *
     * @return URL to the remote JSON Web Key Set.
     */
    @Override
    @NotNull
    @NonNull
    public String getUrl() {
        return url;
    }

    /**
     * Remote JSON Web Key set url. e.g. https://.../.well-known/jwks.json
     * @param url Remote JSON Web Key set url.
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     *
     * @return Representation the KeyType for this JWKS signature configuration. KeyType is the kty parameter in a JSON Web Key (JWK).
     */
    @Override
    @Nullable
    public KeyType getKeyType() {
        return keyType;
    }

    /**
     * Representation of the kty parameter in a JSON Web Key (JWK). Default value (RSA).
     * @param keyType Representation of the kty parameter in a JSON Web Key (JWK).
     */
    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    @Override
    @PositiveOrZero
    public int getRetryAttempts() {
        return retryAttempts;
    }

    /**
     * Number of additional attempts to fetch the JSON Web Key Set when an attempt fails or returns an unparseable response. Retries happen while the request that triggered the fetch waits. Default value {@value #DEFAULT_RETRY_ATTEMPTS} (no retries).
     * @param retryAttempts The number of retries after the initial attempt.
     */
    public void setRetryAttempts(int retryAttempts) {
        this.retryAttempts = retryAttempts;
    }

    @Override
    @NonNull
    public Duration getRetryDelay() {
        return retryDelay;
    }

    /**
     * Delay between attempts to fetch the JSON Web Key Set. Default value 0 (retry immediately).
     * @param retryDelay The delay between attempts.
     */
    public void setRetryDelay(@NonNull Duration retryDelay) {
        ArgumentUtils.requireNonNull("retryDelay", retryDelay);
        this.retryDelay = retryDelay;
    }

    @Override
    public boolean isServeStaleOnFailure() {
        return serveStaleOnFailure;
    }

    /**
     * Whether to serve the last successfully fetched JSON Web Key Set when every attempt to fetch it fails. Keys removed from the remote JSON Web Key Set continue to be trusted until a fetch succeeds. Default value {@value #DEFAULT_SERVE_STALE_ON_FAILURE}.
     * @param serveStaleOnFailure {@code true} to serve the last successfully fetched JSON Web Key Set when fetching fails.
     */
    public void setServeStaleOnFailure(boolean serveStaleOnFailure) {
        this.serveStaleOnFailure = serveStaleOnFailure;
    }

    @Override
    @Nullable
    public Duration getStaleMaxAge() {
        return staleMaxAge;
    }

    /**
     * Maximum age of the last successfully fetched JSON Web Key Set that may be served when fetching fails. Only applies when serve-stale-on-failure is enabled. Default value none (no limit).
     * @param staleMaxAge The maximum age.
     */
    public void setStaleMaxAge(@Nullable Duration staleMaxAge) {
        this.staleMaxAge = staleMaxAge;
    }
}
