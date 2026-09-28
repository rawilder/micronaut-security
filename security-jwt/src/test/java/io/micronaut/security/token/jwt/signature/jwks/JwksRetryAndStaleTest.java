package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class JwksRetryAndStaleTest {

    private static final String JWKS_PREFIX = "micronaut.security.token.jwt.signatures.jwks.test.";

    private static RSAKey signingKey;
    private static String token;

    @BeforeAll
    static void createToken() throws JOSEException {
        signingKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
            new JWTClaimsSet.Builder()
                .subject("john")
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                .build());
        jwt.sign(new RSASSASigner(signingKey));
        token = jwt.serialize();
    }

    static Stream<Arguments> fetchers() {
        return Stream.of(
            arguments(CacheableJwkSetFetcher.class, "micronaut.caches.jwks.expire-after-write", "0s"),
            arguments(ReactorCacheJwkSetFetcher.class, JWKS_PREFIX + "cache-expiration", "0"));
    }

    @ParameterizedTest
    @MethodSource("fetchers")
    void byDefaultFailedFetchIsNotRetriedAndStaleKeysAreNotServed(Class<?> fetcherClass, String cacheConfigName, String cacheConfigValue) {
        withServers(fetcherClass, cacheConfigName, cacheConfigValue, Map.of(), (keys, client) -> {
            assertEquals(HttpStatus.OK, status(client));

            keys.failuresRemaining.set(1);
            int requestsBefore = keys.requests.get();
            assertEquals(HttpStatus.UNAUTHORIZED, status(client));
            assertEquals(1, keys.requests.get() - requestsBefore);

            assertEquals(HttpStatus.OK, status(client));
        });
    }

    @ParameterizedTest
    @MethodSource("fetchers")
    void failedFetchIsRetriedWithDelay(Class<?> fetcherClass, String cacheConfigName, String cacheConfigValue) {
        Map<String, Object> config = Map.of(
            JWKS_PREFIX + "retry-attempts", 2,
            JWKS_PREFIX + "retry-delay", "150ms");
        withServers(fetcherClass, cacheConfigName, cacheConfigValue, config, (keys, client) -> {
            assertEquals(HttpStatus.OK, status(client));

            keys.failuresRemaining.set(2);
            int requestsBefore = keys.requests.get();
            long start = System.nanoTime();
            assertEquals(HttpStatus.OK, status(client));
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

            assertEquals(3, keys.requests.get() - requestsBefore);
            assertTrue(elapsedMillis >= 300, "expected two 150ms retry delays, took " + elapsedMillis + "ms");
        });
    }

    @ParameterizedTest
    @MethodSource("fetchers")
    void retriesAreBoundedByRetryAttempts(Class<?> fetcherClass, String cacheConfigName, String cacheConfigValue) {
        withServers(fetcherClass, cacheConfigName, cacheConfigValue, Map.of(JWKS_PREFIX + "retry-attempts", 1), (keys, client) -> {
            assertEquals(HttpStatus.OK, status(client));

            keys.down = true;
            int requestsBefore = keys.requests.get();
            assertEquals(HttpStatus.UNAUTHORIZED, status(client));
            assertEquals(2, keys.requests.get() - requestsBefore);
        });
    }

    @ParameterizedTest
    @MethodSource("fetchers")
    void lastFetchedKeysAreServedWhenEveryAttemptFails(Class<?> fetcherClass, String cacheConfigName, String cacheConfigValue) {
        Map<String, Object> config = Map.of(
            JWKS_PREFIX + "retry-attempts", 1,
            JWKS_PREFIX + "serve-stale-on-failure", true);
        withServers(fetcherClass, cacheConfigName, cacheConfigValue, config, (keys, client) -> {
            assertEquals(HttpStatus.OK, status(client));

            keys.down = true;
            int requestsBefore = keys.requests.get();
            assertEquals(HttpStatus.OK, status(client));
            assertEquals(2, keys.requests.get() - requestsBefore);
            assertEquals(HttpStatus.OK, status(client));

            keys.down = false;
            assertEquals(HttpStatus.OK, status(client));
        });
    }

    @ParameterizedTest
    @MethodSource("fetchers")
    void noKeysAreServedWhenNoFetchHasEverSucceeded(Class<?> fetcherClass, String cacheConfigName, String cacheConfigValue) {
        withServers(fetcherClass, cacheConfigName, cacheConfigValue, Map.of(JWKS_PREFIX + "serve-stale-on-failure", true), (keys, client) -> {
            keys.down = true;
            assertEquals(HttpStatus.UNAUTHORIZED, status(client));
        });
    }

    @ParameterizedTest
    @MethodSource("fetchers")
    void staleKeysOlderThanStaleMaxAgeAreNotServed(Class<?> fetcherClass, String cacheConfigName, String cacheConfigValue) {
        Map<String, Object> config = Map.of(
            JWKS_PREFIX + "serve-stale-on-failure", true,
            JWKS_PREFIX + "stale-max-age", "500ms");
        withServers(fetcherClass, cacheConfigName, cacheConfigValue, config, (keys, client) -> {
            assertEquals(HttpStatus.OK, status(client));

            keys.down = true;
            assertEquals(HttpStatus.OK, status(client));

            sleep(800);
            assertEquals(HttpStatus.UNAUTHORIZED, status(client));
        });
    }

    private static void withServers(Class<?> fetcherClass,
                                    String cacheConfigName,
                                    String cacheConfigValue,
                                    Map<String, Object> jwksConfig,
                                    ServersTest test) {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "JwksRetryAndStaleTestAuthServer"))) {
            KeysController keys = authServer.getApplicationContext().getBean(KeysController.class);
            keys.jwks = new JWKSet(signingKey.toPublicJWK()).toString();

            Map<String, Object> config = new HashMap<>(jwksConfig);
            config.put("spec.name", "JwksRetryAndStaleTest");
            config.put(JWKS_PREFIX + "url", "http://localhost:" + authServer.getPort() + "/keys");
            config.put(cacheConfigName, cacheConfigValue);
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config);
                 HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                assertInstanceOf(fetcherClass, server.getApplicationContext().getBean(JwkSetFetcher.class));
                test.accept(keys, httpClient.toBlocking());
            }
        }
    }

    private static HttpStatus status(BlockingHttpClient client) {
        try {
            return client.exchange(HttpRequest.GET("/secured").bearerAuth(token), String.class).getStatus();
        } catch (HttpClientResponseException e) {
            return e.getStatus();
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    @FunctionalInterface
    private interface ServersTest {
        void accept(KeysController keys, BlockingHttpClient client);
    }

    @Requires(property = "spec.name", value = "JwksRetryAndStaleTest")
    @Controller
    static class SecuredController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/secured")
        String index() {
            return "ok";
        }
    }

    @Requires(property = "spec.name", value = "JwksRetryAndStaleTestAuthServer")
    @Controller
    static class KeysController {
        final AtomicInteger requests = new AtomicInteger();
        final AtomicInteger failuresRemaining = new AtomicInteger();
        volatile boolean down;
        volatile String jwks;

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/keys")
        @Produces(MediaType.APPLICATION_JSON)
        HttpResponse<String> keys() {
            requests.incrementAndGet();
            if (down || failuresRemaining.getAndUpdate(remaining -> Math.max(0, remaining - 1)) > 0) {
                return HttpResponse.serverError();
            }
            return HttpResponse.ok(jwks);
        }
    }
}
