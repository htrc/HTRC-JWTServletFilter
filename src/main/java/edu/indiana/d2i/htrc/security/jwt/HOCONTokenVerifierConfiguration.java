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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class HOCONTokenVerifierConfiguration implements TokenVerifierConfiguration {
    private static final String[] supportedAlgorithms = {
        "HMAC256", "HMAC384", "HMAC512", "RSA256", "RSASHA256", "RSA384", "RSA512"
    };
    private static final String CONFIG_REQUIRED_CLAIMS = "required-claims";
    private static final String CONFIG_SIGNATURE_VERIFICATION_ALGO = "token.verification.algorithm";
    private static final String CONFIG_SIGNATURE_VERIFICATION_SECRET = "token.verification.secret";
    private static final String CONFIG_TOKEN_VERIFICATION_IGNORE_EXPIRATION = "token.verification.ignore.expiration";
    private static final String CONFIG_TOKEN_ISSUER = "token.issuer";
    private static final String CONFIG_TOKEN_ISSUER_ID = "token.issuer.id";
    private static final String CONFIG_TOKEN_ISSUER_SECRET = "token.issuer.secret";
    private static final String CONFIG_TOKEN_ISSUER_PUB_KEY_KEYSTORE = "token.issuer.public-key.keystore";
    private static final String CONFIG_TOKEN_ISSUER_PUB_KEY_KEYSTORE_PASS = "token.issuer.public-key.keystore-password";
    private static final String CONFIG_TOKEN_ISSUER_PUB_KEY_ALIAS = "token.issuer.public-key.publickey-alias";
    private static final String CONFIG_TOKEN_AUDIENCES = "token.audiences";

    private final Config config;

    private HOCONTokenVerifierConfiguration(Config config) {
        this.config = config;
    }

    public static HOCONTokenVerifierConfiguration createInstance(String confFile) {
        return new HOCONTokenVerifierConfiguration(ConfigFactory.parseFile(new File(confFile)));
    }

    public static HOCONTokenVerifierConfiguration createInstance(Config config) {
        return new HOCONTokenVerifierConfiguration(config);
    }

    @Override
    public Algorithm getSignatureVerificationAlgorithm() throws InvalidAlgorithmParameterException {
        if (!config.hasPath(CONFIG_SIGNATURE_VERIFICATION_ALGO)) {
            throw new RuntimeException(
                "Invalid JWT token verification configuration. Missing required configurations: " +
                    CONFIG_SIGNATURE_VERIFICATION_ALGO);
        }
        String signatureVerificationAlgorithm = config
            .getString(CONFIG_SIGNATURE_VERIFICATION_ALGO);
        if (!Arrays.asList(supportedAlgorithms).contains(signatureVerificationAlgorithm)) {
            throw new InvalidAlgorithmParameterException(
                "Algorithm " + signatureVerificationAlgorithm + " is not supported!");
        }

        Issuer issuer = getTokenIssuerConfiguration();

        try {
            return getSignatureVerificationAlgorithm(signatureVerificationAlgorithm, issuer);
        }
        catch (IOException e) {
            throw new RuntimeException("Error while loading public key.", e);
        }
    }

    @Override
    public Set<String> getRequiredClaims() {
        if (config.hasPath(CONFIG_REQUIRED_CLAIMS)) {
            return new HashSet<>(config.getStringList(CONFIG_REQUIRED_CLAIMS));
        }
        return Collections.emptySet();
    }

    @Override
    public Issuer getTokenIssuerConfiguration() {
        if (!config.hasPath(CONFIG_TOKEN_ISSUER)) {
            throw new RuntimeException(
                "Invalid JWT token verification configuration. Missing token issuer configuration.");
        }

        if (!config.hasPath(CONFIG_TOKEN_ISSUER_ID)) {
            throw new RuntimeException(
                "Invalid JWT token verification configuration. Missing token issuer id.");
        }

        String issuerId = config.getString(CONFIG_TOKEN_ISSUER_ID);
        String secret = null;
        String keyStore = null;
        String keyStorePass = null;
        String pubKeyAlias = null;
        if (config.hasPath(CONFIG_TOKEN_ISSUER_SECRET)) {
            secret = config.getString(CONFIG_TOKEN_ISSUER_SECRET);
        }

        if (config.hasPath(CONFIG_TOKEN_ISSUER_PUB_KEY_KEYSTORE)) {
            keyStore = config.getString(CONFIG_TOKEN_ISSUER_PUB_KEY_KEYSTORE);
        }

        if (config.hasPath(CONFIG_TOKEN_ISSUER_PUB_KEY_KEYSTORE_PASS)) {
            keyStorePass = config.getString(CONFIG_TOKEN_ISSUER_PUB_KEY_KEYSTORE_PASS);
        }

        if (config.hasPath(CONFIG_TOKEN_ISSUER_PUB_KEY_ALIAS)) {
            pubKeyAlias = config.getString(CONFIG_TOKEN_ISSUER_PUB_KEY_ALIAS);
        }

        return new Issuer(issuerId, secret, keyStore, keyStorePass, pubKeyAlias);
    }

    @Override
    public Set<String> getAudiences() {
        if (config.hasPath(CONFIG_TOKEN_AUDIENCES)) {
            return new HashSet<>(config.getStringList(CONFIG_TOKEN_AUDIENCES));
        }
        return Collections.emptySet();
    }

    @Override
    public boolean getIgnoreExpiration() {
        return config.hasPath(CONFIG_TOKEN_VERIFICATION_IGNORE_EXPIRATION) && config
            .getBoolean(CONFIG_TOKEN_VERIFICATION_IGNORE_EXPIRATION);
    }

    private static Algorithm getSignatureVerificationAlgorithm(String algorithm,
                                                               Issuer issuerConfig)
        throws IOException {

        switch (algorithm) {
            case "HMAC256":
                return Algorithm.HMAC256(issuerConfig.getSecret().getBytes());
            case "HMAC384":
                return Algorithm.HMAC384(issuerConfig.getSecret().getBytes());
            case "HMAC512":
                return Algorithm.HMAC512(issuerConfig.getSecret().getBytes());
            case "RSASHA256":
            case "RSA256":
                return Algorithm.RSA256((RSAKey) getPubKey(
                    issuerConfig.getKeystore(),
                    issuerConfig.getKeystorePassword(),
                    issuerConfig.getPublicKeyAlias()
                ));
            case "RSA384":
                return Algorithm.RSA384((RSAKey) getPubKey(
                    issuerConfig.getKeystore(),
                    issuerConfig.getKeystorePassword(),
                    issuerConfig.getPublicKeyAlias()
                ));
            case "RSA512":
                return Algorithm.RSA512((RSAKey) getPubKey(
                    issuerConfig.getKeystore(),
                    issuerConfig.getKeystorePassword(),
                    issuerConfig.getPublicKeyAlias()
                ));
            default:
                throw new RuntimeException("Unsupported algorithm " + algorithm);
        }
    }

    private static PublicKey getPubKey(String keystorePath,
                                       String keystorePass,
                                       String pubkeyAlais) {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(readKeyStore(keystorePath), keystorePass.toCharArray());

            Certificate cert = keystore.getCertificate(pubkeyAlais);

            return cert.getPublicKey();
        }
        catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error while loading public key.", e);
        }
    }

    private static InputStream readKeyStore(String path) throws IOException {
        ClassLoader classLoader = HOCONTokenVerifierConfiguration.class.getClassLoader();
        URL keystoreResource = classLoader.getResource(path);
        if (keystoreResource != null) {
            return classLoader.getResource(path).openStream();
        }

        return new FileInputStream(path);
    }
}
