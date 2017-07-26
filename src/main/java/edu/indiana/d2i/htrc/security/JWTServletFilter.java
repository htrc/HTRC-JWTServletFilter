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

package edu.indiana.d2i.htrc.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import edu.indiana.d2i.htrc.security.jwt.TokenVerifier;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class JWTServletFilter implements Filter {
    private static final Log log = LogFactory.getLog(JWTServletFilter.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String PARAM_FILTER_CONFIG = "htrc.jwtfilter.config";

    private Map<String, String> claimToHeaderMappings = new HashMap<String, String>();

    private TokenVerifier tokenVerifier;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // TokenVerifierConfiguration should be HOCON file stored in somewhere in the file system.
        String filterConfigFile = filterConfig.getInitParameter(PARAM_FILTER_CONFIG);
        if (filterConfigFile == null) {
            filterConfigFile = System.getenv(PARAM_FILTER_CONFIG);
            if (filterConfig == null || filterConfig.equals("")) {
                filterConfigFile = "/etc/htrc/jwtfilter.conf";
            }
        }

        JWTServletFilterConfiguration configuration = new JWTServletFilterConfiguration(
            filterConfigFile);

        try {
            this.tokenVerifier = new TokenVerifier(configuration.getTokenVerifierConfiguration());
        }
        catch (InvalidAlgorithmParameterException e) {
            throw new ServletException("Could not initialize token verifier.", e);
        }

        // We map following JWT claims to HTRC specific request headers by default
        claimToHeaderMappings.put("email", "htrc-user-email");
        claimToHeaderMappings.put("sub", "htrc-user-id");
        claimToHeaderMappings.put("iss", "htrc-token-issuer");

        // Any extra claim mappings are loaded from configuration file
        claimToHeaderMappings.putAll(configuration.getClaimMappings());
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        HttpServletRequest req = ((HttpServletRequest) request);
        String authHeader = ((HttpServletRequest) request).getHeader(AUTHORIZATION_HEADER);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            throw new ServletException("Missing or invalid Authorization header.");
        }

        final String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            JWT jwtToken = tokenVerifier.verify(token);

            JWTFilterServletRequestWrapper requestWrapper = new JWTFilterServletRequestWrapper(
                req,
                jwtToken
                    .getSubject()
            );

            for (String c : claimToHeaderMappings.keySet()) {
                Claim claimValue = jwtToken.getClaim(c);
                requestWrapper.putHeader(claimToHeaderMappings.get(c), claimValue.asString());
            }

            chain.doFilter(requestWrapper, response);
        }
        catch (JWTVerificationException exception) {
            throw new ServletException("Token verification failed.", exception);
        }

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

        @Override
        public Enumeration getHeaders(String name) {
            if (this.headers.containsKey(name)) {
                List<String> values = new ArrayList<String>();
                values.add(this.headers.get(name));
                return Collections.enumeration(values);
            }

            return super.getHeaders(name);
        }

        @Override
        public Enumeration getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames());
            for (String key : this.headers.keySet()) {
                names.add(key);
            }
            return Collections.enumeration(names);
        }

        @Override
        public String getRemoteUser() {
            return remoteUser;
        }
    }
}
