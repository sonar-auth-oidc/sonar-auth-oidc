/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2021 Torsten Juergeleit
 * mailto:torsten AT vaulttec DOT org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.vaulttec.sonarqube.auth.oidc;

import org.junit.Test;
import org.sonar.api.CoreProperties;
import org.sonar.api.config.Configuration;
import org.sonar.api.server.http.HttpRequest;
import org.sonar.api.server.http.HttpResponse;
import org.sonar.api.web.FilterChain;
import org.sonar.api.web.HttpFilter;

import java.util.Optional;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class AutoLoginFilterTest {

  private static final String SONAR_URL = "http://acme.com/sonar";

  @Test
  public void testFilter() throws Exception {
    Configuration configurationMock = mock(Configuration.class);
    when(configurationMock.getBoolean("sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY + ".enabled"))
        .thenReturn(Optional.of(true));
    when(configurationMock.get("sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY + ".issuerUri"))
        .thenReturn(Optional.of("http://idp.com"));
    when(configurationMock.get("sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY + ".clientId.secured"))
        .thenReturn(Optional.of("id"));
    when(configurationMock.getBoolean("sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY + ".autoLogin"))
        .thenReturn(Optional.of(true));
    when(configurationMock.get(CoreProperties.SERVER_BASE_URL)).thenReturn(Optional.of(SONAR_URL));

    HttpFilter filter = new AutoLoginFilter(new OidcConfiguration(configurationMock));
    filter.init();
    filter.doGetPattern();

    HttpRequest request = mock(HttpRequest.class);
    when(request.getRequestURI()).thenReturn(String.valueOf(SONAR_URL + "/sessions/new"));
    when(request.getServerName()).thenReturn("acme.com");

    HttpResponse response = mock(HttpResponse.class);
    FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response).sendRedirect(SONAR_URL + "/sessions/init/" + Constants.OIDC_IDENTITY_PROVIDER_KEY + "?return_to=%2Fprojects");

    filter.destroy();
  }

  @Test
  public void testFilterKeepsReturnTo() throws Exception {
    HttpFilter filter = new AutoLoginFilter(new OidcConfiguration(autoLoginConfig(null)));

    HttpRequest request = mock(HttpRequest.class);
    when(request.getRequestURI()).thenReturn(SONAR_URL + "/sessions/new");
    when(request.getParameter("return_to")).thenReturn("/issues?resolved=false&types=BUG#top");

    HttpResponse response = mock(HttpResponse.class);
    filter.doFilter(request, response, mock(FilterChain.class));

    // query and fragment of the requested page must survive as one encoded return_to value
    verify(response).sendRedirect(SONAR_URL + "/sessions/init/" + Constants.OIDC_IDENTITY_PROVIDER_KEY
        + "?return_to=%2Fissues%3Fresolved%3Dfalse%26types%3DBUG%23top");
  }

  @Test
  public void testFilterDefaultReturnToWithContextPath() throws Exception {
    HttpFilter filter = new AutoLoginFilter(new OidcConfiguration(autoLoginConfig("/sonar")));

    HttpRequest request = mock(HttpRequest.class);
    when(request.getRequestURI()).thenReturn(SONAR_URL + "/sessions/new");

    HttpResponse response = mock(HttpResponse.class);
    filter.doFilter(request, response, mock(FilterChain.class));

    verify(response).sendRedirect(SONAR_URL + "/sessions/init/" + Constants.OIDC_IDENTITY_PROVIDER_KEY
        + "?return_to=%2Fsonar%2Fprojects");
  }

  @Test
  public void testFilterIgnoresExternalReturnTo() throws Exception {
    HttpFilter filter = new AutoLoginFilter(new OidcConfiguration(autoLoginConfig(null)));

    for (String bad : new String[] { "https://evil.com/", "//evil.com/", "/\\evil.com", "evil.com", "", " /issues" }) {
      HttpRequest request = mock(HttpRequest.class);
      when(request.getRequestURI()).thenReturn(SONAR_URL + "/sessions/new");
      when(request.getParameter("return_to")).thenReturn(bad);

      HttpResponse response = mock(HttpResponse.class);
      filter.doFilter(request, response, mock(FilterChain.class));

      verify(response).sendRedirect(SONAR_URL + "/sessions/init/" + Constants.OIDC_IDENTITY_PROVIDER_KEY
          + "?return_to=%2Fprojects");
    }
  }

  @Test
  public void testIsRelativePath() {
    assertTrue(AutoLoginFilter.isRelativePath("/"));
    assertTrue(AutoLoginFilter.isRelativePath("/sonar/issues?id=1#x"));
    assertFalse(AutoLoginFilter.isRelativePath(null));
    assertFalse(AutoLoginFilter.isRelativePath(""));
    assertFalse(AutoLoginFilter.isRelativePath("issues"));
    assertFalse(AutoLoginFilter.isRelativePath("//evil.com"));
    assertFalse(AutoLoginFilter.isRelativePath("/\\evil.com"));
    assertFalse(AutoLoginFilter.isRelativePath("http://evil.com/"));
    assertFalse(AutoLoginFilter.isRelativePath("/issues\r\nSet-Cookie: x"));
  }

  private static Configuration autoLoginConfig(String contextPath) {
    Configuration configurationMock = mock(Configuration.class);
    when(configurationMock.getBoolean(OidcConfiguration.ENABLED)).thenReturn(Optional.of(true));
    when(configurationMock.get(OidcConfiguration.ISSUER_URI)).thenReturn(Optional.of("http://idp.com"));
    when(configurationMock.get(OidcConfiguration.CLIENT_ID)).thenReturn(Optional.of("id"));
    when(configurationMock.getBoolean(OidcConfiguration.AUTO_LOGIN)).thenReturn(Optional.of(true));
    when(configurationMock.get(CoreProperties.SERVER_BASE_URL)).thenReturn(Optional.of(SONAR_URL));
    when(configurationMock.get("sonar.web.context")).thenReturn(Optional.ofNullable(contextPath));
    return configurationMock;
  }

  @Test
  public void testFilterDisbled() throws Exception {
    Configuration configurationMock = mock(Configuration.class);
    when(configurationMock.getBoolean("sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY + ".enabled"))
        .thenReturn(Optional.of(true));
    when(configurationMock.get("sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY + ".issuerUri"))
        .thenReturn(Optional.of("http://idp.com"));
    when(configurationMock.get("sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY + ".clientId.secured"))
        .thenReturn(Optional.of("id"));
    when(configurationMock.getBoolean("sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY + ".autoLogin"))
        .thenReturn(Optional.of(false));
    when(configurationMock.get(CoreProperties.SERVER_BASE_URL)).thenReturn(Optional.of(SONAR_URL));

    HttpFilter filter = new AutoLoginFilter(new OidcConfiguration(configurationMock));
    filter.init();
    filter.doGetPattern();

    HttpRequest request = mock(HttpRequest.class);
    when(request.getRequestURL()).thenReturn(String.valueOf(SONAR_URL + "/sessions/new"));
    when(request.getServerName()).thenReturn("acme.com");

    HttpResponse response = mock(HttpResponse.class);

    FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response, never()).sendRedirect(anyString());

    filter.destroy();
  }

  @Test
  public void testFilterTemporarilyDisbled() throws Exception {
    Configuration configurationMock = mock(Configuration.class);
    when(configurationMock.getBoolean(OidcConfiguration.ENABLED)).thenReturn(Optional.of(true));
    when(configurationMock.get(OidcConfiguration.ISSUER_URI)).thenReturn(Optional.of("http://idp.com"));
    when(configurationMock.get(OidcConfiguration.CLIENT_ID)).thenReturn(Optional.of("id"));
    when(configurationMock.getBoolean(OidcConfiguration.AUTO_LOGIN)).thenReturn(Optional.of(true));
    when(configurationMock.get(CoreProperties.SERVER_BASE_URL)).thenReturn(Optional.of(SONAR_URL));

    HttpFilter filter = new AutoLoginFilter(new OidcConfiguration(configurationMock));
    filter.init();
    filter.doGetPattern();

    HttpRequest request = mock(HttpRequest.class);
    when(request.getRequestURL()).thenReturn(String.valueOf(SONAR_URL + "/sessions/new"));
    when(request.getServerName()).thenReturn("acme.com");
    when(request.getHeader("referer")).thenReturn(SONAR_URL + "/?auto-login=false");

    HttpResponse response = mock(HttpResponse.class);

    FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response, never()).sendRedirect(anyString());

    filter.destroy();
  }

}
