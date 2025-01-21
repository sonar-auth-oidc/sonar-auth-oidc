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

import java.io.IOException;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.sonar.api.server.ServerSide;
import org.sonar.api.server.http.HttpRequest;
import org.sonar.api.server.http.HttpResponse;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.api.web.FilterChain;
import org.sonar.api.web.HttpFilter;
import org.sonar.api.web.UrlPattern;

@ServerSide
public class AutoLoginFilter extends HttpFilter {

  private static final Logger LOGGER = Loggers.get(AutoLoginFilter.class);

  private static final String LOGIN_URL = "/sessions/new";
  private static final String OIDC_URL = "/sessions/init/" + OidcIdentityProvider.KEY + "?return_to=";
  private static final String SKIP_REQUEST_PARAM = "auto-login=false";

  private final OidcConfiguration config;

  public AutoLoginFilter(OidcConfiguration config) {
    this.config = config;
  }

  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create(LOGIN_URL);
  }

  @Override
  public void doFilter(HttpRequest request, HttpResponse response, FilterChain chain) throws IOException {
    if (config.isEnabled() && config.isAutoLogin()) {
      String referrer = request.getHeader("referer");
      LOGGER.debug("Referrer: {}", referrer);

      // Skip if disabled via request parameter
      if (referrer == null || !referrer.endsWith(SKIP_REQUEST_PARAM)) {
        String loginPageUrl = config.getBaseUrl() + OIDC_URL + config.getContextPath() + "/projects";
        LOGGER.debug("Redirecting to OIDC login page: {}", loginPageUrl);
        response.sendRedirect(loginPageUrl);
        return;
      }
    }
    chain.doFilter(request, response);
  }

  @Override
  public void init(){
    // Not needed here
  }
  @Override
  public void destroy() {
    // Not needed here
  }

}
