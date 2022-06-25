/*
 * Copyright (C) 2022 jtalbut
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package uk.co.spudsoft.tokenvalidation;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import java.time.Duration;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import uk.co.spudsoft.tokenvalidation.impl.TokenValidatorImpl;

/**
 * Validate JWTs, obtaining keys via OpenID Discovery is necessary.
 * @author jtalbut
 */
public interface TokenValidator {
  
  /**
   * Create a TokenValidator.
   * 
   * @param vertx The Vertx instance that will be used for asynchronous communication with JWKS endpoints.
   * @param acceptableIssuerRegexes List of acceptable issuers.
   * @param defaultJwkCacheDuration Time to keep JWKs in cache if no cache-control: max-age header is found.
   * @return A newly created TokenValidator.
   */
  static TokenValidator create(Vertx vertx, Collection<String> acceptableIssuerRegexes, Duration defaultJwkCacheDuration) {
    JsonWebKeySetHandler openIdDiscoveryHandler = JsonWebKeySetOpenIdDiscoveryHandler.create(WebClient.create(vertx), acceptableIssuerRegexes, defaultJwkCacheDuration);
    return new TokenValidatorImpl(openIdDiscoveryHandler);
  }

  /**
   * Get a copy of the current set of permitted algorithms.
   * @return a copy of the current set of permitted algorithms.
   */
  EnumSet<JsonWebAlgorithm> getPermittedAlgorithms();
  
  /**
   * Replace the current set of permitted algorithms with a new set.
   * @param algorithms The new set of permitted algorithms.
   * @return this for fluent configuration.
   */
  TokenValidator setPermittedAlgorithms(EnumSet<JsonWebAlgorithm> algorithms);
  
  /**
   * Add a single algorithm to the current set of permitted algorithms.
   * @param algorithm The algorithm to add to the current set of permitted algorithms.
   * @return this for fluent configuration.
   */
  TokenValidator addPermittedAlgorithm(JsonWebAlgorithm algorithm);
  
  /**
   * Set to true if the token is required to have an exp claim.
   * @param requireExp true if the token is required to have an exp claim.
   * @return this for fluent configuration.
   */
  TokenValidator setRequireExp(boolean requireExp);

  /**
   * Set to true if the token is required to have an nbf claim.
   * @param requireNbf true if the token is required to have an nbf claim.
   * @return this for fluent configuration.
   */
  TokenValidator setRequireNbf(boolean requireNbf);

  /**
   * Set the maximum amount of time that can pass between the exp and now.
   * @param timeLeewaySeconds the maximum amount of time that can pass between the exp and now.
   * @return this for fluent configuration.
   */
  TokenValidator setTimeLeewaySeconds(long timeLeewaySeconds);

  /**
   * Validate the token and either throw an exception or return it's constituent parts.
   * @param token             The token.
   * @param requiredAudList   List of audiences, all of which must be claimed by the token. 
   * @param ignoreRequiredAud Do not check for required audiences.
   * @return The token's parts.
   */
  Future<JWT> validateToken(String token, List<String> requiredAudList, boolean ignoreRequiredAud);

}
