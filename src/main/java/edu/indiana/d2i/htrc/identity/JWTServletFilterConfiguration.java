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

package edu.indiana.d2i.htrc.identity;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.util.*;

public class JWTServletFilterConfiguration {

  private static final String CONFIG_REQUIRED_CLAIMS = "jwtfilter.required-claims";
  private static final String CONFIG_SIGNATURE_VERIFICATION_ALGO = "jwtfilter.signature-verification.algorithm";
  private static final String CONFIG_SIGNATURE_VERIFICATION_SECRET = "jwtfilter.signature-verification.secret";
  private static final String CONFIG_CLAIM_MAPPINGS = "jwtfilter.claim-mappings";

  private final Config config;

  public JWTServletFilterConfiguration(String configFile) {
    this.config = ConfigFactory.parseFile(new File(configFile));
  }

  public Set<String> getRequiredClaims() {
    return new HashSet<>(config.getStringList(CONFIG_REQUIRED_CLAIMS));
  }

  public SignatureVerificationConfiguration getSignatureVerificationConfig() throws InvalidAlgorithmParameterException {
    return new SignatureVerificationConfiguration(config.getString(CONFIG_SIGNATURE_VERIFICATION_ALGO),
        config.getString(CONFIG_SIGNATURE_VERIFICATION_SECRET));
  }

  public Map<String, String> getClaimMappings() {
    Map<String, String> mappings = new HashMap<>();

    config.getConfig(CONFIG_CLAIM_MAPPINGS).entrySet().stream().forEach((entry) -> {
      mappings.put(entry.getKey(), entry.getValue().toString());
    });

    return mappings;
  }

  public static class SignatureVerificationConfiguration {
    private static final String[] supportedAlgorithms = {"HMAC256", "HMAC384", "HMAC512", "RSA256", "RSA384", "RSA512"};

    // Any algorithm supported by https://github.com/auth0/java-jwt
    private final String algorithm;

    // Matching secret value for the algorithm. e.g. If the algorithm is RSA256, the secret should be RSA public key file
    private final String secret;

    public SignatureVerificationConfiguration(String algorithm, String secret) throws InvalidAlgorithmParameterException {
      verifyAlgorithm(algorithm);
      this.algorithm = algorithm;
      this.secret = secret;
    }

    private void verifyAlgorithm(String algorithm) throws InvalidAlgorithmParameterException {
      if (!Arrays.asList(supportedAlgorithms).contains(algorithm)) {
        throw new InvalidAlgorithmParameterException("Algorithm " + algorithm + " is not supported!");
      }
    }

    public String getAlgorithm() {
      return algorithm;
    }

    public String getSecret() {
      return secret;
    }
  }
}
