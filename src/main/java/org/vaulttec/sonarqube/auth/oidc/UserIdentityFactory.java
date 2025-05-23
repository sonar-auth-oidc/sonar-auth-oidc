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

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.UserIdentity;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.vaulttec.sonarqube.auth.oidc.OidcConfiguration.*;

/**
 * Converts OpenID Connect {@link UserInfo} to SonarQube {@link UserIdentity}.
 */
@ServerSide
public class UserIdentityFactory {

  private final OidcConfiguration config;

  public UserIdentityFactory(OidcConfiguration config) {
    this.config = config;
  }

  public UserIdentity create(UserInfo userInfo) {
    UserIdentity.Builder builder = UserIdentity.builder().setProviderId(userInfo.getSubject().getValue())
        .setProviderLogin(getLogin(userInfo)).setName(getName(userInfo)).setEmail(userInfo.getEmailAddress());
    if (config.syncGroups()) {
      builder.setGroups(getGroups(userInfo));
    }
    return builder.build();
  }

  private String getLogin(UserInfo userInfo) {
    switch (config.loginStrategy()) {
    case LOGIN_STRATEGY_PREFERRED_USERNAME:
      if (userInfo.getPreferredUsername() == null) {
        throw new IllegalStateException("Claim 'preferred_username' is missing in user info - "
            + "make sure your OIDC provider supports this claim in the id token or at the user info endpoint");
      }
      return userInfo.getPreferredUsername();
    case LOGIN_STRATEGY_PROVIDER_ID:
      return userInfo.getSubject().getValue();
    case LOGIN_STRATEGY_EMAIL:
      if (userInfo.getEmailAddress() == null) {
        throw new IllegalStateException("Claim 'email' is missing in user info - "
            + "make sure your OIDC provider supports this claim in the id token or at the user info endpoint");
      }
      return userInfo.getEmailAddress();
    case LOGIN_STRATEGY_UNIQUE:
      return generateUniqueLogin(userInfo);
    case LOGIN_STRATEGY_CUSTOM_CLAIM:
      if (userInfo.getStringClaim(config.loginStrategyCustomClaimName()) == null) {
        throw new IllegalStateException(
            "Custom claim '" + config.loginStrategyCustomClaimName() + "' is missing in user info - "
                + "make sure your OIDC provider supports this claim in the id token or at the user info endpoint");
      }
      return userInfo.getStringClaim(config.loginStrategyCustomClaimName());
    default:
      throw new IllegalStateException(format("Login strategy not supported: %s", config.loginStrategy()));
    }
  }

  private String generateUniqueLogin(UserInfo userInfo) {
    return format("%s@%s", userInfo.getSubject().getValue(), Constants.OIDC_IDENTITY_PROVIDER_KEY);
  }

  private String getName(UserInfo userInfo) {
    String name = userInfo.getName() != null ? userInfo.getName() : userInfo.getPreferredUsername();
    if (name == null) {
      throw new IllegalStateException("Claims 'name' and 'preferred_username' are missing in user info - "
          + "make sure your OIDC provider supports at least one of these claims in the id token or at the user info endpoint");
    }
    return name;
  }

  private Set<String> getGroups(UserInfo userInfo) {
    Object groupsClaim = userInfo.getClaim(config.syncGroupsClaimName());
    if (groupsClaim == null) {
      throw new IllegalStateException("Groups claim '" + config.syncGroupsClaimName() + "' is missing in user info - "
          + "make sure your OIDC provider supports this claim in the id token or at the user info endpoint");
    }
    List<String> groups;
    if (groupsClaim instanceof List) {
      groups = (List) groupsClaim;
    } else { // String
      if (((String) groupsClaim).contains(",")) {
        // comma-separated list of groups
        groups = Stream.of(((String) groupsClaim).split(","))
            .map(String::trim)
            .collect(Collectors.toList());
      } else {
        // single group
        groups = Collections.singletonList((String) groupsClaim);
      }
    }
    return new HashSet<>(groups);
  }

}
