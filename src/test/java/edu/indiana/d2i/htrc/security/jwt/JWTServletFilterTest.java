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
import com.auth0.jwt.algorithms.Algorithm;
import edu.indiana.d2i.htrc.security.JWTServletFilter;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class JWTServletFilterTest {
    @Test
    public void testDoFilter() throws IOException, ServletException, ParseException {
        JWTServletFilter filter = new JWTServletFilter();
        HttpServletRequest mockReq = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
        FilterChain mockFilterChain = new TestFilterChain();
        FilterConfig mockFilterConfig = Mockito.mock(FilterConfig.class);
        ServletContext mockServletContext = Mockito.mock(ServletContext.class);

        String testConfigPath = getResourcePath("test-basic.conf");

        Mockito
            .when(mockServletContext.getResource(testConfigPath))
            .thenReturn(new File(testConfigPath).toURI().toURL());

        // mock filter config init parameter
        Mockito
            .when(mockFilterConfig.getInitParameter("htrc.jwtfilter.config"))
            .thenReturn(testConfigPath);

        Mockito
            .when(mockFilterConfig.getServletContext())
            .thenReturn(mockServletContext);

        // mock the getRequestURI() response
        Mockito
            .when(mockReq.getRequestURI())
            .thenReturn("/secure-api");

        // mock getHeader("Authorization")
        Mockito
            .when(mockReq.getHeader("Authorization"))
            .thenReturn("Bearer " + generateJWTToken());

        BufferedReader br = new BufferedReader(new StringReader("test"));
        // mock the getReader() call
        Mockito.when(mockReq.getReader()).thenReturn(br);

        filter.init(mockFilterConfig);
        filter.doFilter(mockReq, mockResp, mockFilterChain);
        filter.destroy();

        HttpServletRequest request =
            (HttpServletRequest) ((TestFilterChain) mockFilterChain).getRequest();

        Assert.assertEquals(request.getRemoteUser(), "admin");
        Assert.assertEquals(request.getHeader("htrc-email"), "shliyana@indiana.edu");
    }

    @Test
    public void testRemoteUser() throws IOException, ServletException, ParseException {
        JWTServletFilter filter = new JWTServletFilter();
        HttpServletRequest mockReq = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
        FilterChain mockFilterChain = new TestFilterChain();
        FilterConfig mockFilterConfig = Mockito.mock(FilterConfig.class);
        ServletContext mockServletContext = Mockito.mock(ServletContext.class);

        String testConfigPath = getResourcePath("test-remote-user.conf");

        Mockito
                .when(mockServletContext.getResource(testConfigPath))
                .thenReturn(new File(testConfigPath).toURI().toURL());

        // mock filter config init parameter
        Mockito
                .when(mockFilterConfig.getInitParameter("htrc.jwtfilter.config"))
                .thenReturn(testConfigPath);

        Mockito
                .when(mockFilterConfig.getServletContext())
                .thenReturn(mockServletContext);

        // mock the getRequestURI() response
        Mockito
                .when(mockReq.getRequestURI())
                .thenReturn("/secure-api");

        // mock getHeader("Authorization")
        Mockito
                .when(mockReq.getHeader("Authorization"))
                .thenReturn("Bearer " + generateJWTToken());

        BufferedReader br = new BufferedReader(new StringReader("test"));
        // mock the getReader() call
        Mockito.when(mockReq.getReader()).thenReturn(br);

        filter.init(mockFilterConfig);
        filter.doFilter(mockReq, mockResp, mockFilterChain);
        filter.destroy();

        HttpServletRequest request =
                (HttpServletRequest) ((TestFilterChain) mockFilterChain).getRequest();

        Assert.assertEquals(request.getRemoteUser(), "test-htrc-uid");
        Assert.assertEquals(request.getHeader("htrc-email"), "shliyana@indiana.edu");
    }

    private String getResourcePath(String resource) {
        ClassLoader classLoader = getClass().getClassLoader();
        return classLoader.getResource(resource).getFile();
    }

    private String generateJWTToken() throws UnsupportedEncodingException, ParseException {
        // create a token that expires 1 hour from now
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, 1);
        Date date = calendar.getTime();

        return JWT.create()
                  .withIssuer("https://devenv-notls-is:443/oauth2/token")
                  .withClaim("sub", "admin")
                  .withClaim("email", "shliyana@indiana.edu")
                  .withClaim("htrc-uid","test-htrc-uid")
                  .withExpiresAt(date)
                  .sign(Algorithm.RSA256(getPrivateKey()));
    }

    private RSAKey getPrivateKey() {
        ClassLoader classLoader = getClass().getClassLoader();
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(classLoader.getResourceAsStream("jwt-test.jks"), "jwttest".toCharArray());

            return (RSAKey) keystore.getKey("jwt-test", "jwttest".toCharArray());
        }
        catch (KeyStoreException | CertificateException | IOException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error while loading public key.", e);
        }
    }

    private static class TestFilterChain implements FilterChain {
        private ServletRequest request;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {
            this.request = request;
        }

        public ServletRequest getRequest() {
            return request;
        }
    }
}
