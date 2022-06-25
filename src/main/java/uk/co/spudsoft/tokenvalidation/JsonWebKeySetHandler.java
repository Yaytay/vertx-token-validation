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

/**
 * Perform OpenID Connect discovery as per <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">openid-connect-discovery-1_0</a>.
 * @author jtalbut
 */
public interface JsonWebKeySetHandler {
 
  /**
   * Confirm that the issuer matches at least one of the configured acceptable issuer regular expressions.
   * @param issuer the issuer to confirm.
   * @throws IllegalArgumentException if the issuer is not in the list of acceptable issuers.
   */
  void validateIssuer(String issuer) throws IllegalArgumentException;
  
  /**
   * Find a JWK for the given issuer and kid.
   * 
   * @param issuer the issuer of the JWT (and JWK).
   * @param kid The key ID being sought.
   * @return A Future that will be completed with a JWK.
   */
  Future<JWK> findJwk(String issuer, String kid);
         
  
}
