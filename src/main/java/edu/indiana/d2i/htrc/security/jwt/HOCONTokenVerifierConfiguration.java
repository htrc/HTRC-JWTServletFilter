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


import com.auth0.jwt.algorithms.Algorithm;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import edu.indiana.d2i.htrc.security.jwt.api.TokenVerifierConfiguration;

import java.io.File;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class HOCONTokenVerifierConfiguration implements TokenVerifierConfiguration {
  private static final String[] supportedAlgorithms = {"HMAC256", "HMAC384", "HMAC512", "RSA256", "RSA384", "RSA512"};
  private static final String CONFIG_REQUIRED_CLAIMS = "required-claims";
  private static final String CONFIG_SIGNATURE_VERIFICATION_ALGO = "token.verification.algorithm";
  private static final String CONFIG_SIGNATURE_VERIFICATION_SECRET = "token.verification.secret";
  private static final String CONFIG_TOKEN_ISSUER = "token.issuer";
  private static final String CONFIG_TOKEN_AUDIENCES = "token.audiences";

  private final Config config;

  public static HOCONTokenVerifierConfiguration createInstance(String confFile) {
    return new HOCONTokenVerifierConfiguration(ConfigFactory.parseFile(new File(confFile)));
  }

  public static HOCONTokenVerifierConfiguration createInstance(Config config) {
    return new HOCONTokenVerifierConfiguration(config);
  }

  private HOCONTokenVerifierConfiguration(Config config) {
    this.config = config;
  }


  @Override
  public Algorithm getSignatureVerificationAlgorithm() throws InvalidAlgorithmParameterException {
    if (!config.hasPath(CONFIG_SIGNATURE_VERIFICATION_ALGO) || !config.hasPath(CONFIG_SIGNATURE_VERIFICATION_SECRET)) {
      throw new RuntimeException("Invalid JWT token verification configuration. Missing required configurations: " +
          CONFIG_SIGNATURE_VERIFICATION_ALGO + " or " + CONFIG_SIGNATURE_VERIFICATION_SECRET);
    }
    String signatureVerificationAlgorithm = config.getString(CONFIG_SIGNATURE_VERIFICATION_ALGO);
    String secret = config.getString(CONFIG_SIGNATURE_VERIFICATION_SECRET);
    if (!Arrays.asList(supportedAlgorithms).contains(signatureVerificationAlgorithm)) {
      throw new InvalidAlgorithmParameterException("Algorithm " + signatureVerificationAlgorithm + " is not supported!");
    }

    return getSignatureVerificationAlgorithm(signatureVerificationAlgorithm, secret);
  }

  @Override
  public Set<String> getRequiredClaims() {
    if (config.hasPath(CONFIG_REQUIRED_CLAIMS)) {
      return new HashSet<>(config.getStringList(CONFIG_REQUIRED_CLAIMS));
    }
    return Collections.emptySet();
  }

  @Override
  public String getTokenIssuer() {
    if (!config.hasPath(CONFIG_TOKEN_ISSUER)) {
      throw new RuntimeException("Invalid JWT token verification configuration. Missing required configuration: " + CONFIG_TOKEN_ISSUER);
    }
    return config.getString(CONFIG_TOKEN_ISSUER);
  }

  @Override
  public Set<String> getAudiences() {
    if (config.hasPath(CONFIG_TOKEN_AUDIENCES)) {
      return new HashSet<>(config.getStringList(CONFIG_TOKEN_AUDIENCES));
    }
    return Collections.emptySet();
  }

  private static Algorithm getSignatureVerificationAlgorithm(String algorithm, String secret) {
    switch (algorithm) {
      case "HMAC256":
        return Algorithm.HMAC256(secret.getBytes());
      case "HMAC384":
        return Algorithm.HMAC384(secret.getBytes());
      case "HMAC512":
        return Algorithm.HMAC512(secret.getBytes());
      case "RSA256":
        return Algorithm.RSA256((RSAKey) getPubKey(secret));
      case "RSA384":
        return Algorithm.RSA384((RSAKey) getPubKey(secret));
      case "RSA512":
        return Algorithm.RSA512((RSAKey) getPubKey(secret));
      default:
        throw new RuntimeException("Unsupported algorithm " + algorithm);
    }
  }

  private static PublicKey getPubKey(String filename) {
    try {
      byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());

      X509EncodedKeySpec spec =
          new X509EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePublic(spec);
    } catch (Exception e) {
      throw new RuntimeException("Error while loading public key.", e);
    }
  }
}
