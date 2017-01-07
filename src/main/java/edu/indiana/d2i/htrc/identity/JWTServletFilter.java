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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class JWTServletFilter implements Filter {
  private static final Logger log = LoggerFactory.getLogger(JWTServletFilter.class);

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";
  private static final String PARAM_REQUIRED_CLAIMS = "htrc.identity.required.claims";
  private static final String PARAM_CLAIM_TO_HEADER_MAPPING = "htrc.identity.claim.to.header.mapping";
  private static final String PARAM_TOKEN_SIGNING_PUBLIC_KEY = "htrc.identity.token.signing.pubkey";

  private Set<String> requiredClaims = new HashSet<String>();
  private Map<String, String> claimToHeaderMappings = new HashMap<String, String>();
  private PublicKey publicKey;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // Default claims
    requiredClaims.add("email");
    requiredClaims.add("sub");
    requiredClaims.add("iss");

    String requiredClaimsStr = filterConfig.getInitParameter(PARAM_REQUIRED_CLAIMS);
    if (requiredClaimsStr != null) {
      List<String> rawClaims = Arrays.<String>asList(requiredClaimsStr.split(","));
      for (String rawClaim : rawClaims) {
        requiredClaims.add(rawClaim.trim());
      }
    }

    // Default mappings
    claimToHeaderMappings.put("email", "htrc-user-email");
    claimToHeaderMappings.put("sub", "htrc-user-id");
    claimToHeaderMappings.put("iss", "htrc-token-issuer");

    String rawClaimMappings = filterConfig.getInitParameter(PARAM_CLAIM_TO_HEADER_MAPPING);

    if (rawClaimMappings != null && rawClaimMappings.length() > 0) {
      List<String> claimMappings = Arrays.<String>asList(rawClaimMappings.split(","));
      for (String claimMapping : claimMappings) {
        String[] mapping = claimMapping.split("=");

        if (mapping.length == 2) {
          claimToHeaderMappings.put(mapping[0].trim(), mapping[1].trim());
        } else {
          log.warn("Invalid claim mapping: " + claimMapping);
        }
      }
    }

    String pubKeyPath = filterConfig.getInitParameter(PARAM_TOKEN_SIGNING_PUBLIC_KEY);

    if (pubKeyPath == null || pubKeyPath.length() < 1) {
      throw new ServletException("Missing required parameter " + PARAM_TOKEN_SIGNING_PUBLIC_KEY);
    }

    try {
      this.publicKey = getPubKey(pubKeyPath.trim());
    } catch (Exception e) {
      throw new ServletException("Couldn't load token verification public key.", e);
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
    JWTFilterServletRequestWrapper requestWrapper = new JWTFilterServletRequestWrapper(req);
    try {
      JWTVerifier verifier = JWT.require(Algorithm.RSA256(
          (RSAKey) publicKey))
          .withIssuer("auth0")
          .build(); //Reusable verifier instance
      JWT jwt = (JWT) verifier.verify(token);

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

  public static PublicKey getPubKey(String filename)
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

    /**
     * Constructs a request object wrapping the given request.
     *
     * @param request
     * @throws IllegalArgumentException if the request is null
     */
    public JWTFilterServletRequestWrapper(HttpServletRequest request) {
      super(request);
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
