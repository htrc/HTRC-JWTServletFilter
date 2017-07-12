/**
 * Copyright 2016 Milinda Pathirage
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.indiana.d2i.htrc.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.InvalidClaimException;
import edu.indiana.d2i.htrc.security.jwt.api.TokenVerifierConfiguration;

import java.security.InvalidAlgorithmParameterException;

public class TokenVerifier {

  private final TokenVerifierConfiguration configuration;
  private final JWTVerifier jwtVerifier;

  public TokenVerifier(TokenVerifierConfiguration configuration) throws InvalidAlgorithmParameterException {
    this.configuration = configuration;
    long leeway = 60;
    if (configuration.getIgnoreExpiration()) {
      leeway = 10 * 31622400;
    }

    if (configuration.getAudiences() != null && !configuration.getAudiences().isEmpty()) {
      this.jwtVerifier = JWT.require(configuration.getSignatureVerificationAlgorithm())
          .withIssuer(configuration.getTokenIssuerConfiguration().getId())
          .withAudience(configuration.getAudiences().toArray(new String[configuration.getAudiences().size()]))
          .acceptExpiresAt(leeway)
          .build();
    } else {
      this.jwtVerifier = JWT.require(configuration.getSignatureVerificationAlgorithm())
          .withIssuer(configuration.getTokenIssuerConfiguration().getId())
          .acceptExpiresAt(leeway)
          .build();
    }
  }

  public JWT verify(String jwtToken) {
    JWT token = (JWT) jwtVerifier.verify(jwtToken);
    for (String claim: configuration.getRequiredClaims()){
      if (token.getClaim(claim) == null){
        throw new InvalidClaimException("Missing required claim " + claim);
      }
    }

    return token;
  }
}
