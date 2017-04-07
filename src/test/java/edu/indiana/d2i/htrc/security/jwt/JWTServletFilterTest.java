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

    String token = "eyJ4NXQiOiJObUptT0dVeE16WmxZak0yWkRSaE5UWmxZVEExWXpkaFpUUmlPV0UwTldJMk0ySm1PVGMxWkEiLCJraWQiOiJkMGVjNTE0YTMyYjZmODhjMGFiZDEyYTI4NDA2OTliZGQzZGViYTlkIiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoiRWxFMnJrYWtXMG04czJtc2dQRWxiZyIsInN1YiI6ImFkbWluIiwiYXVkIjpbIjJmWXE1WkVJeTFLbnpweFg4bkpRTnJXUHRCTWEiLCJodHRwczpcL1wvZGV2ZW52LW5vdGxzLWlzOjQ0M1wvb2F1dGgyXC90b2tlbiJdLCJyb2xlIjpbIkFwcGxpY2F0aW9uXC9hbmFseXRpY3MtZ2F0ZXdheS0xMCIsIkFwcGxpY2F0aW9uXC9hbmFseXRpY3MtZ2F0ZXdheS0yMSIsIkFwcGxpY2F0aW9uXC9hbmFseXRpY3MtZ2F0ZXdheS0yMiIsIkFwcGxpY2F0aW9uXC9hbmFseXRpY3MtZ2F0ZXdheS0yMCIsIkludGVybmFsXC9ldmVyeW9uZSIsImFkbWluIiwiQXBwbGljYXRpb25cL2FuYWx5dGljcy1nYXRld2F5LTE0IiwiQXBwbGljYXRpb25cL2FuYWx5dGljcy1nYXRld2F5LTE1IiwiQXBwbGljYXRpb25cL2FuYWx5dGljcy1nYXRld2F5LTIzIiwiQXBwbGljYXRpb25cL2FuYWx5dGljcy1nYXRld2F5LTEzIiwiQXBwbGljYXRpb25cL2FuYWx5dGljcy1nYXRld2F5LTE4IiwiQXBwbGljYXRpb25cL2FuYWx5dGljcy1nYXRld2F5LTE2IiwiQXBwbGljYXRpb25cL2FuYWx5dGljcy1nYXRld2F5LTE3Il0sImF6cCI6IjJmWXE1WkVJeTFLbnpweFg4bkpRTnJXUHRCTWEiLCJhdXRoX3RpbWUiOjE0OTE1NDExODQsImlzcyI6Imh0dHBzOlwvXC9kZXZlbnYtbm90bHMtaXM6NDQzXC9vYXV0aDJcL3Rva2VuIiwiZXhwIjoxNDkxNTc3MTg1LCJpYXQiOjE0OTE1NDExODUsImVtYWlsIjoiYWRtaW5Ad3NvMi5jb20ifQ.JTETU7Ib3EmrefbFZla246Zv-r65Ih4FvZX_bu7QzI7BbAgznUjTFTaH2tFnFOUxB5k0r0q5NMvwcHIV6KPvVui06QYReYVwjN3TZ4lJxVO0dicroIpMBkmUE6tSoUrgRqVveEZfnTEH2-p1cH9U4JodNqKF2JIcTjbiuU3EWuI";
    // mock getHeader("Authorization")
    Mockito.when(mockReq.getHeader("Authorization")).thenReturn("Bearer " + token);

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

  private String getResourcePath(String resource) {
    ClassLoader classLoader = getClass().getClassLoader();
    return classLoader.getResource(resource).getFile();
  }
}
