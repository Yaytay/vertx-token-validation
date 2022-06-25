# vertx-jwt-validation

[![Latest release](https://img.shields.io/github/release/yaytay/verx-token-validation.svg)](https://github.com/yaytay/verx-token-validation/latest)
[![License](https://img.shields.io/github/license/yaytay/verx-token-validation)](https://github.com/yaytay/vertx-token-validation/blob/main/LICENCE.md)
[![Issues](https://img.shields.io/github/issues/yaytay/vertx-token-validation)](https://github.com/yaytay/vertx-token-validation/issues)
[![Build Status](https://github.com/yaytay/vertx-token-validation/actions/workflows/buildtest.yml/badge.svg)](https://github.com/Yaytay/vertx-token-validation/actions/workflows/buildtest.yml)
[![CodeCov](https://codecov.io/gh/Yaytay/vertx-token-validation/branch/main/graph/badge.svg?token=ACHVK20T9Q)](https://codecov.io/gh/Yaytay/vertx-token-validation)

A basic library to parse and verify JWTs, with OpenID discovery used to obtain JWKs asynchronously (via Vertx).

The library uses vertx-web, but does not use vertx-auth-common and does not attempt to provide a Vertx Auth solution (there is no implementation of AuthorizationProvider in this library).

# Getting Started
Release versions should be in maven central, so declare the dependency in your pom.xml:
```xml
    <dependency>
      <groupId>uk.co.spudsoft</groupId>
      <artifactId>vertx-token-validation</artifactId>
      <version>0.0.13</version>
    </dependency>
```

Then create a TokenValidator and ask it to validate a token:
```java
  // Create a TokenValidator
  TokenValidator validator = TokenValidator.create(
          // The Vertx instance that will be used to make web requests
          vertx, 
          // Array of acceptable issuers (as regular expressions).
          Arrays.asList("http://localhost.*"), 
          // Time to cache JWK keys for if they do have a cache-control(max-age) header
          Duration.of(1, ChronoUnit.MINUTES)
  );
  // By default the TokenValidator will accept RS256, RS384 and RS512, any others that must be handled must be specified.
  validator.addPermittedAlgorithm(jwa);
  // In this setup a token need not expire (this is bad practice, just to demonstrate that the validator has some configuration options).
  valiator.setRequireExp(false);

  // Get the JWT in its usual 3 x Base64 form.
  String authHeader = exchange.getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION.toString());
  if (authHeader.startsWith("Bearer ")) {
    String token = authHeader.substring(7);
    // Call the validator, requiring the token to contain "my-service" as an audience claim.
    validator.validateToken(token, Arrays.asList("my-service"), false)
            .compose(signedJwt -> {
              // Standard claims can be extracted with named methods
              logger.debug("Token valid from: {}", signedJwt.getNotBeforeLocalDateTime());
              // Non-standard claims can be extracted with the claim method
              logger.debug("Token tags: {}", signedJwt.getClaim("tags"));
            });
```



# Building

It's a standard maven project, just build it with:
```sh
mvn clean install
```

There are minimal dependencies, at runtime it's jackson and slf4j, but there are quite a few maven plugins.
