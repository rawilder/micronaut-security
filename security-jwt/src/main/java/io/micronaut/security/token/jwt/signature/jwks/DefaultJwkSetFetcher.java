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

import com.nimbusds.jose.jwk.JWKSet;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.optim.StaticOptimizations;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Default implementation of {@link JwkSetFetcher} for {@link JWKSet}.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Singleton
public class DefaultJwkSetFetcher implements JwkSetFetcher<JWKSet> {
    public static final Optimizations OPTIMIZATIONS = StaticOptimizations.get(Optimizations.class).orElse(new Optimizations(Collections.emptyMap()));

    private static final Logger LOG = LoggerFactory.getLogger(DefaultJwkSetFetcher.class);

    private final JwksClient jwksClient;
    private final Map<String, JwksSignatureConfiguration> jwksSignatureConfigurations;
    private final Map<String, FetchedJwkSet> lastFetchedJwkSets = new ConcurrentHashMap<>();

    /**
     * @param jwksClient JSON Web Key Set client
     * @deprecated Use {@link #DefaultJwkSetFetcher(JwksClient, Map)} instead. Retries and serving stale JSON Web Key Sets are not supported with this constructor.
     */
    @Deprecated(forRemoval = true, since = "5.5.0")
    public DefaultJwkSetFetcher(JwksClient jwksClient) {
        this(jwksClient, Collections.emptyMap());
    }

    /**
     * @param jwksClient JSON Web Key Set client
     * @param jwksSignatureConfigurations JSON Web Key Set configurations keyed by name
     * @since 5.5.0
     */
    @Inject
    public DefaultJwkSetFetcher(JwksClient jwksClient, Map<String, JwksSignatureConfiguration> jwksSignatureConfigurations) {
        this.jwksClient = jwksClient;
        this.jwksSignatureConfigurations = jwksSignatureConfigurations;
    }

    @Override
    @NonNull
    @SingleResult
    public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
        if (url == null) {
            return Mono.empty();
        }
        Optional<Publisher<JWKSet>> optionalJWKSetPublisher = OPTIMIZATIONS.findJwkSet(url)
                .map(Supplier::get)
                .map(Mono::just);
        return optionalJWKSetPublisher.orElseGet(() -> load(providerName, url));
    }

    @Override
    public void clearCache(@NonNull String url) {
        OPTIMIZATIONS.clear(url);
    }

    @SingleResult
    private Publisher<JWKSet> load(@Nullable String providerName, @NonNull String url) {
        JwksSignatureConfiguration configuration = providerName != null ? jwksSignatureConfigurations.get(providerName) : null;
        if (configuration == null) {
            return loadOnce(providerName, url);
        }
        Mono<JWKSet> jwkSet = loadWithRetries(providerName, url, configuration.getRetryAttempts(), configuration.getRetryDelay());
        if (!configuration.isServeStaleOnFailure()) {
            return jwkSet;
        }
        return jwkSet
            .doOnNext(fetched -> lastFetchedJwkSets.put(url, new FetchedJwkSet(fetched, Instant.now())))
            .switchIfEmpty(Mono.defer(() -> lastFetchedJwkSet(url, configuration.getStaleMaxAge())));
    }

    private Mono<JWKSet> loadWithRetries(@Nullable String providerName, @NonNull String url, int retriesRemaining, @NonNull Duration retryDelay) {
        Mono<JWKSet> attempt = loadOnce(providerName, url);
        if (retriesRemaining <= 0) {
            return attempt;
        }
        return attempt.switchIfEmpty(Mono.defer(() -> {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Retrying JWK Set fetch from {} ({} retries remaining)", url, retriesRemaining);
            }
            Mono<JWKSet> retry = loadWithRetries(providerName, url, retriesRemaining - 1, retryDelay);
            return retryDelay.isZero() ? retry : Mono.delay(retryDelay).then(retry);
        }));
    }

    private Mono<JWKSet> lastFetchedJwkSet(@NonNull String url, @Nullable Duration staleMaxAge) {
        FetchedJwkSet lastFetched = lastFetchedJwkSets.get(url);
        if (lastFetched == null) {
            return Mono.empty();
        }
        Duration age = Duration.between(lastFetched.fetchedAt(), Instant.now());
        if (staleMaxAge != null && age.compareTo(staleMaxAge) > 0) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Fetching JWK Set from {} failed and the last successfully fetched JWK Set is older than the maximum stale age {}", url, staleMaxAge);
            }
            return Mono.empty();
        }
        if (LOG.isWarnEnabled()) {
            LOG.warn("Fetching JWK Set from {} failed, serving the JWK Set successfully fetched {} ago", url, age);
        }
        return Mono.just(lastFetched.jwkSet());
    }

    private Mono<JWKSet> loadOnce(@Nullable String providerName, @NonNull String url) {
        return Mono.from(jwksClient.load(providerName, url))
                .mapNotNull(jwkSetContent -> {
                    try {
                        return JWKSet.parse(jwkSetContent);
                    } catch (ParseException e) {
                        if (LOG.isErrorEnabled()) {
                            LOG.error("Exception parsing JWK Set response from " + url, e);
                        }
                    }
                    return null;
                });
    }

    private record FetchedJwkSet(@NonNull JWKSet jwkSet, @NonNull Instant fetchedAt) {
    }

    /**
     * AOT Optimizations.
     */
    public static class Optimizations {
        private final Map<String, Supplier<JWKSet>> suppliers;

        /**
         *
         * @param suppliers Map with key being the Jwks uri and value the Json Web Key Set.
         */
        public Optimizations(@NonNull Map<String, Supplier<JWKSet>> suppliers) {
            this.suppliers = suppliers;
        }

        /**
         *
         * @param url Json Web Key Set Url
         * @return a Json Web Key  supplier or an empty optional if not cached
         */
        public Optional<Supplier<JWKSet>> findJwkSet(@NonNull String url) {
            return Optional.ofNullable(suppliers.get(url));
        }

        /**
         * @param url Json Web Key Set Url
         */
        public void clear(@NonNull String url) {
            suppliers.remove(url);
        }
    }
}
