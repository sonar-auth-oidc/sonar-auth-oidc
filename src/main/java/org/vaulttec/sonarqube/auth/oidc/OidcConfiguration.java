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

import org.sonar.api.CoreProperties;
import org.sonar.api.config.Configuration;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.server.ServerSide;

import javax.annotation.CheckForNull;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static java.lang.String.valueOf;
import static org.sonar.api.CoreProperties.CATEGORY_SECURITY;
import static org.sonar.api.PropertyType.*;

@ServerSide
public class OidcConfiguration {

  private static final String PREFIX = "sonar.auth." + Constants.OIDC_IDENTITY_PROVIDER_KEY;

  private static final String CATEGORY = CATEGORY_SECURITY;
  private static final String SUBCATEGORY = Constants.OIDC_IDENTITY_PROVIDER_KEY;

  static final String ENABLED = PREFIX + ".enabled";
  static final String AUTO_LOGIN = PREFIX + ".autoLogin";
  static final String ISSUER_URI = PREFIX + ".issuerUri";
  static final String CLIENT_ID = PREFIX + ".clientId.secured";
  static final String CLIENT_SECRET = PREFIX + ".clientSecret.secured";
  static final String ALLOW_USERS_TO_SIGN_UP = PREFIX + ".allowUsersToSignUp";

  static final String ID_TOKEN_SIG_ALG = PREFIX + ".idTokenSigAlg";
  static final String ID_TOKEN_SIG_ALG_HMAC = "HS256";
  static final String ID_TOKEN_SIG_ALG_RSA = "RS256";
  static final String ID_TOKEN_SIG_ALG_ECDSA = "ES256";

  static final String SCOPES = PREFIX + ".scopes";
  private static final String SCOPES_DEFAULT_VALUE = "openid email profile";

  static final String LOGIN_STRATEGY = PREFIX + ".loginStrategy";
  static final String LOGIN_STRATEGY_UNIQUE = "Unique";
  static final String LOGIN_STRATEGY_PROVIDER_ID = "Same as OpenID Connect login";
  static final String LOGIN_STRATEGY_PREFERRED_USERNAME = "Preferred username";
  static final String LOGIN_STRATEGY_EMAIL = "Email";
  static final String LOGIN_STRATEGY_CUSTOM_CLAIM = "Custom claim";
  static final String LOGIN_STRATEGY_DEFAULT_VALUE = LOGIN_STRATEGY_PREFERRED_USERNAME;

  static final String LOGIN_STRATEGY_CUSTOM_CLAIM_NAME = PREFIX + ".loginStrategy.customClaim.name";
  private static final String LOGIN_STRATEGY_CUSTOM_CLAIM_NAME_DEFAULT_VALUE = "upn";

  static final String GROUPS_SYNC = PREFIX + ".groupsSync";
  static final String GROUPS_SYNC_CLAIM_NAME = PREFIX + ".groupsSync.claimName";
  private static final String GROUPS_SYNC_CLAIM_NAME_DEFAULT_VALUE = "groups";

  static final String ICON_PATH = PREFIX + ".iconPath";
  private static final String ICON_PATH_DEFAULT_VALUE = "/static/authoidc/openid.svg";

  static final String BACKGROUND_COLOR = PREFIX + ".backgroundColor";
  private static final String BACKGROUND_COLOR_DEFAULT_VALUE = "#236a97";

  static final String LOGIN_BUTTON_TEXT = PREFIX + ".loginButtonText";
  private static final String LOGIN_BUTTON_TEXT_DEFAULT_VALUE = "OpenID Connect";

  private final Configuration config;

  public OidcConfiguration(Configuration config) {
    this.config = config;
  }

  public String getBaseUrl() {
    Optional<String> baseUrl = config.get(CoreProperties.SERVER_BASE_URL);
    return baseUrl.orElse("");
  }

  public String getContextPath() {
    Optional<String> contextPath = config.get("sonar.web.context");
    return contextPath.orElse("");
  }

  public boolean isEnabled() {
    return config.getBoolean(ENABLED).orElse(false) && issuerUri() != null && clientId() != null;
  }

  public boolean isAutoLogin() {
    return config.getBoolean(AUTO_LOGIN).orElse(false);
  }

  @CheckForNull
  public String issuerUri() {
    return config.get(ISSUER_URI).orElse(null);
  }

  @CheckForNull
  public String clientId() {
    return config.get(CLIENT_ID).orElse(null);
  }

  public String clientSecret() {
    return config.get(CLIENT_SECRET).orElse(null);
  }

  public String scopes() {
    return config.get(SCOPES).orElse("openid");
  }

  public String idTokenSignAlgorithm() {
    return config.get(ID_TOKEN_SIG_ALG).orElse(null);
  }

  public boolean allowUsersToSignUp() {
    return config.getBoolean(ALLOW_USERS_TO_SIGN_UP).orElse(false);
  }

  public String loginStrategy() {
    return config.get(LOGIN_STRATEGY).orElse(null);
  }

  public String loginStrategyCustomClaimName() {
    return config.get(LOGIN_STRATEGY_CUSTOM_CLAIM_NAME).orElse(null);
  }

  public boolean syncGroups() {
    return config.getBoolean(GROUPS_SYNC).orElse(false);
  }

  public String syncGroupsClaimName() {
    return config.get(GROUPS_SYNC_CLAIM_NAME).orElse(null);
  }

  public String iconPath() {
    return config.get(ICON_PATH).orElse(null);
  }

  public String backgroundColor() {
    return config.get(BACKGROUND_COLOR).orElse(null);
  }

  public String loginButtonText() {
    return config.get(LOGIN_BUTTON_TEXT).orElse(null);
  }

  public static List<PropertyDefinition> definitions() {
    int index = 1;
    return Arrays.asList(
        PropertyDefinition
            .builder(ENABLED).name("Enabled")
            .description("Enable OpenID Connect users to login. "
                + "Value is ignored if issuer URI and client ID are not defined.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(BOOLEAN).defaultValue(valueOf(false)).index(index++)
            .build(),
        PropertyDefinition.builder(AUTO_LOGIN).name("Auto-Login")
            .description("Skip the SonarQube login page and forward to OpenID Connect authentication. "
                + "Auto-Login can be skipped by using the URL \"&lt;sonarServerBaseURL&gt;/?auto-login=false\".")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(BOOLEAN).defaultValue(valueOf(false)).index(index++)
            .build(),
        PropertyDefinition.builder(ISSUER_URI).name("Issuer URI")
            .description("The issuer URI of an OpenID Connect provider. "
                + "This URI is used to retrieve the provider's metadata via OpenID Connect Discovery from the path \"/.well-known/openid-configuration\".")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).index(index++).build(),
        PropertyDefinition.builder(CLIENT_ID).name("Client ID").description("The ID of an OpenID Connect Client.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).index(index++).build(),
        PropertyDefinition.builder(CLIENT_SECRET).name("Client secret")
            .description("The shared secret of a non-public client. "
                + "This is only needed for an OpenID Connect client with access type \"confidential\".")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).index(index++).build(),
        PropertyDefinition.builder(SCOPES).name("Scopes")
            .description("OAuth scopes ('openid' is required) to pass in the Open ID Connect authorize request.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).defaultValue(SCOPES_DEFAULT_VALUE).index(index++)
            .build(),
        PropertyDefinition.builder(ID_TOKEN_SIG_ALG).name("ID token signature algorithm")
            .description("If activated then the ID token is validated with the selected algorithm"
                + " (HMAC, RSA or ECDSA - using SHA-256 hash)")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(SINGLE_SELECT_LIST)
            .options(ID_TOKEN_SIG_ALG_HMAC, ID_TOKEN_SIG_ALG_RSA, ID_TOKEN_SIG_ALG_ECDSA).index(index++).build(),
        PropertyDefinition.builder(ALLOW_USERS_TO_SIGN_UP).name("Allow users to sign-up")
            .description("Allow new users to authenticate. "
                + "When set to 'false', only existing users will be able to authenticate to the server.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(BOOLEAN).defaultValue(valueOf(true)).index(index++)
            .build(),
        PropertyDefinition.builder(LOGIN_STRATEGY).name("Login generation strategy").description(format(
            "When the login strategy is set to '%s', the provider login will be auto-generated the first time so that it is unique."
                + " When the login strategy is set to '%s', the provider login will be the OpenID Connect provider's internal user ID."
                + " When the login strategy is set to '%s', the provider login will be the OpenID Connect provider's user email."
                + " When the login strategy is set to '%s', the provider login will be the OpenID Connect provider's user name."
                + " When the login strategy is set to '%s', the provider login will be a custom claim in OpenID Connect provider's ID token.",
            LOGIN_STRATEGY_UNIQUE, LOGIN_STRATEGY_PROVIDER_ID, LOGIN_STRATEGY_EMAIL, LOGIN_STRATEGY_PREFERRED_USERNAME,
            LOGIN_STRATEGY_CUSTOM_CLAIM)).category(CATEGORY).subCategory(SUBCATEGORY).type(SINGLE_SELECT_LIST)
            .defaultValue(LOGIN_STRATEGY_DEFAULT_VALUE)
            .options(LOGIN_STRATEGY_UNIQUE, LOGIN_STRATEGY_PROVIDER_ID, LOGIN_STRATEGY_EMAIL,
                LOGIN_STRATEGY_PREFERRED_USERNAME, LOGIN_STRATEGY_CUSTOM_CLAIM)
            .index(index++).build(),
        PropertyDefinition.builder(LOGIN_STRATEGY_CUSTOM_CLAIM_NAME).name("Login strategy custom claim")
            .description("Name of the claim in case login generation strategy is set to custom claim.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING)
            .defaultValue(LOGIN_STRATEGY_CUSTOM_CLAIM_NAME_DEFAULT_VALUE).index(index++).build(),
        PropertyDefinition.builder(GROUPS_SYNC).name("Synchronize groups")
            .description("For each of his Open ID Connect userinfo groups claim entries,"
                + " the user will be associated to a group with the same name (if it exists) in SonarQube.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(BOOLEAN).defaultValue(valueOf(false)).index(index++)
            .build(),
        PropertyDefinition.builder(GROUPS_SYNC_CLAIM_NAME).name("Groups claim name")
            .description("Name of the claim in the Open ID Connect userinfo holding the user's groups.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).defaultValue(GROUPS_SYNC_CLAIM_NAME_DEFAULT_VALUE)
            .index(index++).build(),
        PropertyDefinition.builder(ICON_PATH).name("Icon path")
            .description("Path to the provider icon - default icon shipped with plugin \"" + ICON_PATH_DEFAULT_VALUE
                + "\" or external URL (for example \"http://www.mydomain/myincon.png\").")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).defaultValue(ICON_PATH_DEFAULT_VALUE)
            .index(index++).build(),
        PropertyDefinition.builder(BACKGROUND_COLOR).name("Background color").description(
            "Background color (hexadecimal value, for example \"#205081\") for the provider button displayed in the login form.")
            .category(CATEGORY).subCategory(SUBCATEGORY).type(STRING).defaultValue(BACKGROUND_COLOR_DEFAULT_VALUE)
            .index(index++).build(),
        PropertyDefinition.builder(LOGIN_BUTTON_TEXT).name("Login button text")
            .description("The text in SonarQube's login button added to 'Log in with '.").category(CATEGORY)
            .subCategory(SUBCATEGORY).type(STRING).defaultValue(LOGIN_BUTTON_TEXT_DEFAULT_VALUE).index(index).build());
  }

}
