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
import io.vertx.ext.web.client.WebClient;
import java.time.Duration;
import java.util.Collection;
import uk.co.spudsoft.tokenvalidation.impl.JWKSOpenIdDiscoveryHandlerImpl;

/**
 * Perform OpenID Connect discovery as per <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">openid-connect-discovery-1_0</a>.
 * 
 * It is not usually necessary to use this interface for anything other than the Factory method.
 * 
 * @author jtalbut
 */
public interface JsonWebKeySetOpenIdDiscoveryHandler extends JsonWebKeySetHandler {
 
  /**
   * Construct an instance of the implementation class.
   * @param webClient Vertx WebClient instance, so that the discovery handler can make asynchronous web requests.
   * @param acceptableIssuerRegexes Collection of regular expressions that any issues will be checked against.
   * @param defaultJwkCacheDuration Time to keep JWKs in cache if no cache-control: max-age header is found.
   * 
   * It is vital for the security of any system using OpenID Connect Discovery that it is only used with trusted issuers
   * (otherwise any key that has an RFC compliant discovery endpoint will be accepted).
   * Equally the acceptable issuers must be accessed via https for the environment to offer any security, so it is strongly recommended that
   * all regexes start 'https://' (this is not enforced in the code to make test setups easier).
   * 
   * @return a newly created instance of the implementation class.
   */
  static JsonWebKeySetOpenIdDiscoveryHandler create(WebClient webClient, Collection<String> acceptableIssuerRegexes, Duration defaultJwkCacheDuration) {
    return new JWKSOpenIdDiscoveryHandlerImpl(webClient, acceptableIssuerRegexes, defaultJwkCacheDuration.toSeconds());
  }
  
  /**
   * Obtain the discovery data for an issuer as per <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">openid-connect-discovery-1_0</a>.
   * 
   * If discovery data has not already been cached this will result in a call to 
   * <pre>
   * issuer + (issuer.endsWith("/") ? "" : "/") + ".well-known/openid-configuration"
   * </pre>
   * 
   * The resulting Discovery Data will be cached against the issuer.
   * 
   * @param issuer The issuer to obtain the discovery data for.
   * @return A Future that will be completed with the Discovery Data.
   */
  Future<DiscoveryData> performOpenIdDiscovery(String issuer);
  
  /**
   * Find a JWK using the jwks_uri value from the Discovery Data.
   * 
   * The resulting JWK will be cached against the jwks_uri.
   * 
   * @param discoveryData The Discovery Data that contains the jwks_uri.
   * @param kid The key ID being sought.
   * @return A Future that will be completed with the JWK.
   */
  Future<JWK> findJwk(DiscoveryData discoveryData, String kid);
  
}
