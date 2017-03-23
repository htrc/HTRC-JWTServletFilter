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
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;

public class JWTServletFilterTest {
  @Test
  public void testDoFilter() throws IOException, ServletException {
    JWTServletFilter filter = new JWTServletFilter();
    HttpServletRequest mockReq = Mockito.mock(HttpServletRequest.class);
    HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
    FilterChain mockFilterChain = Mockito.mock(FilterChain.class);
    FilterConfig mockFilterConfig = Mockito.mock(FilterConfig.class);

    // mock filter config init parameter
    Mockito.when(mockFilterConfig.getInitParameter("htrc.jwtfilter.config")).thenReturn(getResourcePath("test-basic.conf"));

    // mock the getRequestURI() response
    Mockito.when(mockReq.getRequestURI()).thenReturn("/");

    // mock getHeader("Authorization")
    Mockito.when(mockReq.getHeader("Authorization")).thenReturn("Bearer " + getValidJWTToken());

    BufferedReader br = new BufferedReader(new StringReader("test"));
    // mock the getReader() call
    Mockito.when(mockReq.getReader()).thenReturn(br);

    filter.init(mockFilterConfig);
    filter.doFilter(mockReq, mockResp, mockFilterChain);
    filter.destroy();
  }

  private String getValidJWTToken() throws UnsupportedEncodingException {
    return JWT.create()
        .withIssuer("https://localhost:9443/oauth/token")
        .withClaim("sub", "admin")
        .withClaim("iss", "https://localhost:9443/oauth/token")
        .withClaim("email", "shliyana@indiana.edu")
        .sign(Algorithm.HMAC256("testsecret"));
  }

  private String getResourcePath(String resource){
    ClassLoader classLoader = getClass().getClassLoader();
    return classLoader.getResource(resource).getFile();
  }
}
