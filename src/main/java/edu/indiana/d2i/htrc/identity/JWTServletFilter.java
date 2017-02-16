/**
 * Copyright 2017 Trustees of Indiana University
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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class JWTServletFilter implements Filter {
  private static final Logger log = LoggerFactory.getLogger(JWTServletFilter.class);

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";
  private static final String PARAM_FILTER_CONFIG = "htrc.jwtfilter.config";

  private Set<String> requiredClaims = new HashSet<String>();
  private Map<String, String> claimToHeaderMappings = new HashMap<String, String>();
  private Algorithm signatureVerificationAlgorithm;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // Configuration should be HOCON file stored in somewhere in the file system.
    String filterConfigFile = filterConfig.getInitParameter(PARAM_FILTER_CONFIG);
    if (filterConfigFile == null) {
      filterConfigFile = "/etc/htrc/jwtfilter.conf";
    }

    JWTServletFilterConfiguration configuration = new JWTServletFilterConfiguration(filterConfigFile);

    // Following claims are required by default
    requiredClaims.add("email");
    requiredClaims.add("sub");
    requiredClaims.add("iss");

    // Any extra claims required by the servlet
    requiredClaims.addAll(configuration.getRequiredClaims());

    // We map following JWT claims to HTRC specific request headers by default
    claimToHeaderMappings.put("email", "htrc-user-email");
    claimToHeaderMappings.put("sub", "htrc-user-id");
    claimToHeaderMappings.put("iss", "htrc-token-issuer");

    // Any extra claim mappings are loaded from configuration file
    claimToHeaderMappings.putAll(configuration.getClaimMappings());

    try {
      signatureVerificationAlgorithm = getSignatureVerificationAlgorithm(configuration.getSignatureVerificationConfig());
    } catch (Exception e) {
      throw new ServletException("Cannot initialize signature verification algorithm.", e);
    }
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest req = ((HttpServletRequest) request);
    String authHeader = ((HttpServletRequest) request).getHeader(AUTHORIZATION_HEADER);

    if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
      throw new ServletException("Missing or invalid Authorization header.");
    }

    final String token = authHeader.substring(BEARER_PREFIX.length());

    try {
      JWTVerifier verifier = JWT.require(signatureVerificationAlgorithm)
          .withIssuer("auth0")
          .build(); //Reusable verifier instance
      JWT jwt = (JWT) verifier.verify(token);

      JWTFilterServletRequestWrapper requestWrapper = new JWTFilterServletRequestWrapper(req, jwt.getSubject());

      for (String c : requiredClaims) {
        Claim claimValue = jwt.getClaim(c);

        if (claimToHeaderMappings.containsKey(c)) {
          requestWrapper.putHeader(claimToHeaderMappings.get(c), claimValue.asString());
        } else {
          requestWrapper.putHeader(c, claimValue.asString());
        }
      }

      chain.doFilter(requestWrapper, response);
    } catch (JWTVerificationException exception) {
      throw new ServletException("Token verification failed.", exception);
    }

  }

  private static Algorithm getSignatureVerificationAlgorithm(JWTServletFilterConfiguration.SignatureVerificationConfiguration config) throws Exception {
    switch (config.getAlgorithm()) {
      case "HMAC256":
        return Algorithm.HMAC256(config.getSecret().getBytes());
      case "HMAC384":
        return Algorithm.HMAC384(config.getSecret().getBytes());
      case "HMAC512":
        return Algorithm.HMAC512(config.getSecret().getBytes());
      case "RSA256":
        return Algorithm.RSA256((RSAKey) getPubKey(config.getSecret()));
      case "RSA384":
        return Algorithm.RSA384((RSAKey) getPubKey(config.getSecret()));
      case "RSA512":
        return Algorithm.RSA512((RSAKey) getPubKey(config.getSecret()));
      default:
        throw new InvalidAlgorithmParameterException("Unsupported algoruthm " + config.getAlgorithm());
    }
  }

  private static PublicKey getPubKey(String filename)
      throws Exception {

    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());

    X509EncodedKeySpec spec =
        new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

  @Override
  public void destroy() {

  }

  public static class JWTFilterServletRequestWrapper extends HttpServletRequestWrapper {

    private final Map<String, String> headers = new HashMap<String, String>();
    private final String remoteUser;

    /**
     * Constructs a request object wrapping the given request.
     *
     * @param request
     * @throws IllegalArgumentException if the request is null
     */
    public JWTFilterServletRequestWrapper(HttpServletRequest request, String remoteUser) {
      super(request);
      this.remoteUser = remoteUser;
    }

    @Override
    public String getRemoteUser() {
      return remoteUser;
    }

    public void putHeader(String header, String value) {
      headers.put(header, value);
    }

    @Override
    public String getHeader(String name) {
      if (headers.containsKey(name)) {
        return headers.get(name);
      }

      return super.getHeader(name);
    }
  }
}
