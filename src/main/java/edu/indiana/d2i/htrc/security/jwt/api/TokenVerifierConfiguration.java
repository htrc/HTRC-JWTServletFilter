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

package edu.indiana.d2i.htrc.security.jwt.api;

import com.auth0.jwt.algorithms.Algorithm;
import java.security.InvalidAlgorithmParameterException;
import java.util.Set;

public interface TokenVerifierConfiguration {
    Algorithm getSignatureVerificationAlgorithm() throws InvalidAlgorithmParameterException;

    Set<String> getRequiredClaims();

    Issuer getTokenIssuerConfiguration();

    Set<String> getAudiences();

    boolean getIgnoreExpiration();

    class Issuer {
        private final String id;
        private final String secret;
        private final String keystore;
        private final String keystorePassword;
        private final String publicKeyAlias;


        public Issuer(
            String id, String secret, String keystore, String keystorePassword,
            String publicKeyAlias) {
            this.id = id;
            this.secret = secret;
            this.keystore = keystore;
            this.keystorePassword = keystorePassword;
            this.publicKeyAlias = publicKeyAlias;
        }

        public String getId() {
            return id;
        }

        public String getKeystore() {
            return keystore;
        }

        public String getKeystorePassword() {
            return keystorePassword;
        }

        public String getPublicKeyAlias() {
            return publicKeyAlias;
        }

        public String getSecret() {
            return secret;
        }
    }
}
