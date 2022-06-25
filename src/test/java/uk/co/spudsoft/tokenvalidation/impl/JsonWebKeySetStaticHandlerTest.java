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
package uk.co.spudsoft.tokenvalidation.impl;

import io.vertx.core.json.JsonObject;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import uk.co.spudsoft.tokenvalidation.JWK;
import uk.co.spudsoft.tokenvalidation.JsonWebKeySetStaticHandler;

/**
 *
 * @author jtalbut
 */
public class JsonWebKeySetStaticHandlerTest {
  
  @Test
  public void testIssuerRegexes() {
    assertThrows(IllegalArgumentException.class, () -> new JWKSStaticSetHandlerImpl(Arrays.asList()));
    assertThrows(IllegalArgumentException.class, () -> new JWKSStaticSetHandlerImpl(Arrays.asList("")));
    assertThrows(IllegalArgumentException.class, () -> new JWKSStaticSetHandlerImpl(Arrays.asList("[a-")));
  }
  
  @Test
  public void testValidateIssuer() {
    JsonWebKeySetStaticHandler impl = new JWKSStaticSetHandlerImpl(Arrays.asList("bob"));
    assertThrows(IllegalArgumentException.class, () -> impl.validateIssuer("fred"));
  }

  
  @Test
  public void testAddKey() throws Exception {
    
    JsonWebKeySetStaticHandler impl = JsonWebKeySetStaticHandler.create();
    
    assertTrue(impl.findJwk("issuer", "kid").failed());
    JWK jwk = new JWK(0, new JsonObject("{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"kid\":\"518a90bb-7cc7-4e5c-ab27-152fc8043bdd\",\"x\":\"uH_4yaa1mSj6NzIAOrrkMkfDRpNklKKgHBc8a-7Hslk\"}"));
    impl.addKey("issuer", jwk);
    assertEquals("sig", impl.findJwk("issuer", "518a90bb-7cc7-4e5c-ab27-152fc8043bdd").result().getUse());
    impl.removeKey("issuer", jwk.getKid());
    assertTrue(impl.findJwk("issuer", "518a90bb-7cc7-4e5c-ab27-152fc8043bdd").failed());
  }

}
