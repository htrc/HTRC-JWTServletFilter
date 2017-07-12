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
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
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
import java.text.SimpleDateFormat;
import java.util.Date;

public class JWTServletFilterTest {
  @Test
  public void testDoFilter() throws IOException, ServletException, ParseException {
    JWTServletFilter filter = new JWTServletFilter();
    HttpServletRequest mockReq = Mockito.mock(HttpServletRequest.class);
    HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
    FilterChain mockFilterChain = new TestFilterChain();
    FilterConfig mockFilterConfig = Mockito.mock(FilterConfig.class);

    // mock filter config init parameter
    Mockito.when(mockFilterConfig.getInitParameter("htrc.jwtfilter.config")).thenReturn(getResourcePath("test-basic.conf"));

    // mock the getRequestURI() response
    Mockito.when(mockReq.getRequestURI()).thenReturn("/secure-api");

    // mock getHeader("Authorization")
    Mockito.when(mockReq.getHeader("Authorization")).thenReturn("Bearer " + generateJWTToken());

    BufferedReader br = new BufferedReader(new StringReader("test"));
    // mock the getReader() call
    Mockito.when(mockReq.getReader()).thenReturn(br);

    filter.init(mockFilterConfig);
    filter.doFilter(mockReq, mockResp, mockFilterChain);
    filter.destroy();

    Assert.assertEquals(((HttpServletRequest)((TestFilterChain)mockFilterChain).getRequest()).getRemoteUser(), "admin");
    Assert.assertEquals(((HttpServletRequest)((TestFilterChain)mockFilterChain).getRequest()).getHeader("htrc-email"), "shliyana@indiana.edu");
  }

  private static class TestFilterChain implements FilterChain {
    private ServletRequest request;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
      this.request = request;
    }

    public ServletRequest getRequest() {
      return request;
    }
  }


  private String generateJWTToken() throws UnsupportedEncodingException, ParseException {
    String oldstring = "2011-01-18 00:00:00.0";
    Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.S").parse(oldstring);
    return JWT.create()
        .withIssuer("https://devenv-notls-is:443/oauth2/token")
        .withClaim("sub", "admin")
        .withClaim("email", "shliyana@indiana.edu")
        .withExpiresAt(date)
        .sign(Algorithm.RSA256(getPrivateKey()));
  }

  private RSAKey getPrivateKey() {
    ClassLoader classLoader = getClass().getClassLoader();
    KeyStore keystore = null;
    try {
      keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(classLoader.getResourceAsStream("jwt-test.jks"), "jwttest".toCharArray());

      return (RSAKey) keystore.getKey("jwt-test", "jwttest".toCharArray());
    } catch (KeyStoreException | CertificateException | IOException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
      throw new RuntimeException("Error while loading public key.", e);
    }
  }

  private String getResourcePath(String resource) {
    ClassLoader classLoader = getClass().getClassLoader();
    return classLoader.getResource(resource).getFile();
  }
}
