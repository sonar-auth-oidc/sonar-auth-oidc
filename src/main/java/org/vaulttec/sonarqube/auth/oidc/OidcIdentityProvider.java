/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2017 Torsten Juergeleit
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

import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.Display;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

@ServerSide
public class OidcIdentityProvider implements OAuth2IdentityProvider {

  private static final Logger LOGGER = Loggers.get(OidcIdentityProvider.class);
  public static final String KEY = "oidc";

  private final OidcConfiguration config;
  private final OidcClient client;
  private final UserIdentityFactory userIdentityFactory;

  public OidcIdentityProvider(OidcConfiguration config, OidcClient client, UserIdentityFactory userIdentityFactory) {
    this.config = config;
    this.client = client;
    this.userIdentityFactory = userIdentityFactory;
  }

  @Override
  public String getKey() {
    return KEY;
  }

  @Override
  public String getName() {
    return config.loginButtonText();
  }

  @Override
  public Display getDisplay() {
    return Display.builder().setIconPath(config.iconPath()).setBackgroundColor(config.backgroundColor()).build();
  }

  @Override
  public boolean isEnabled() {
    return config.isEnabled();
  }

  @Override
  public boolean allowsUsersToSignUp() {
    return config.allowUsersToSignUp();
  }

  @Override
  public void init(InitContext context) {
    LOGGER.debug("Starting authentication workflow");
    if (!isEnabled()) {
      throw new IllegalStateException("OpenID Connect authentication is disabled");
    }
    String state = context.generateCsrfState();
    AuthenticationRequest authenticationRequest = client.createAuthenticationRequest(context.getCallbackUrl(), state);
    LOGGER.debug("Redirecting to authentication endpoint");
    context.redirectTo(authenticationRequest.toURI().toString());
  }

  @Override
  public void callback(CallbackContext context) {
    LOGGER.debug("Handling authentication response");
    context.verifyCsrfState();
    AuthorizationCode authorizationCode = client.getAuthorizationCode(context.getHttpRequest());
    UserInfo userInfo = client.getUserInfo(authorizationCode, context.getCallbackUrl());
    UserIdentity userIdentity = userIdentityFactory.create(userInfo);
    LOGGER.debug("Authenticating user '{}' with groups {}", userIdentity.getProviderLogin(), userIdentity.getGroups());
    context.authenticate(userIdentity);
    LOGGER.debug("Redirecting to requested page");
    context.redirectToRequestedPage();
  }

}
