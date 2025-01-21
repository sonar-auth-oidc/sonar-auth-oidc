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

import org.junit.Before;
import org.junit.Test;
import org.sonar.api.CoreProperties;
import org.sonar.api.config.Configuration;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.vaulttec.sonarqube.auth.oidc.OidcConfiguration.*;

public class OidcConfigurationTest {

  private static final String SONAR_URL = "https://sonar.acme.com";
  private static final String AUTH_URL = "https://auth.acme.com";


  protected static String property(String suffix){
    return "sonar.auth" + OidcIdentityProvider.KEY + "." + suffix;
  }

  private void mockConfigValue(String key, String value){
    when(config.get(property(key))).thenReturn(Optional.of(value));

    if("true".equals(value) || "false".equals(value)){
      when(config.getBoolean(property(key))).thenReturn(Optional.of(Boolean.parseBoolean(value)));
    }
  }


  private Configuration config;
  private OidcConfiguration underTest;

  @Before
  public void setUp(){
    config = mock(Configuration.class);
    when(config.get(any())).thenReturn(Optional.empty());
    when(config.getBoolean(any())).thenReturn(Optional.empty());
    underTest = new OidcConfiguration(config);
  }

  @Test
  public void is_enabled() {
    mockConfigValue(OidcConfiguration.ENABLED, "true");
    mockConfigValue(OidcConfiguration.ISSUER_URI, AUTH_URL);
    mockConfigValue(OidcConfiguration.CLIENT_ID, "id");
    assertThat(underTest.isEnabled()).isTrue();

    mockConfigValue(OidcConfiguration.ENABLED, "false");
    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_issuer_uri_is_null() {
    mockConfigValue(OidcConfiguration.ENABLED, "true");
    mockConfigValue(OidcConfiguration.ISSUER_URI, (String) null);
    mockConfigValue(OidcConfiguration.CLIENT_ID, "id");

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_client_id_is_null() {
    mockConfigValue(OidcConfiguration.ENABLED, "true");
    mockConfigValue(OidcConfiguration.ISSUER_URI, AUTH_URL);
    mockConfigValue(OidcConfiguration.CLIENT_ID, (String) null);

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_auto_login() {
    mockConfigValue(OidcConfiguration.AUTO_LOGIN, "true");

    assertThat(underTest.isAutoLogin()).isTrue();
  }

  @Test
  public void configure_issuer_uri() throws Exception {
    mockConfigValue(OidcConfiguration.ISSUER_URI, AUTH_URL);

    assertThat(underTest.issuerUri()).isEqualTo(AUTH_URL);
  }

  @Test
  public void return_client_id() {
    mockConfigValue(OidcConfiguration.CLIENT_ID, "id");
    assertThat(underTest.clientId()).isEqualTo("id");
  }

  @Test
  public void return_client_secret() {
    mockConfigValue(OidcConfiguration.CLIENT_SECRET, "secret");
    assertThat(underTest.clientSecret()).isEqualTo("secret");
  }

  @Test
  public void return_id_token_sign_algorithm() {
    mockConfigValue(OidcConfiguration.ID_TOKEN_SIG_ALG, ID_TOKEN_SIG_ALG_RSA);
    assertThat(underTest.idTokenSignAlgorithm()).isEqualTo(ID_TOKEN_SIG_ALG_RSA);
  }

  @Test
  public void default_id_token_sign_algorithm() {
    assertThat(underTest.idTokenSignAlgorithm()).isNull();
  }

  @Test
  public void return_login_strategy() {
    mockConfigValue(OidcConfiguration.LOGIN_STRATEGY, LOGIN_STRATEGY_PROVIDER_ID);
    assertThat(underTest.loginStrategy()).isEqualTo(LOGIN_STRATEGY_PROVIDER_ID);
  }

  @Test
  public void default_login_strategy_is_preferred_username() {
    assertThat(underTest.loginStrategy()).isEqualTo(LOGIN_STRATEGY_PREFERRED_USERNAME);
  }

  @Test
  public void allow_users_to_sign_up() {
    mockConfigValue(OidcConfiguration.ALLOW_USERS_TO_SIGN_UP, "true");
    assertThat(underTest.allowUsersToSignUp()).isTrue();

    mockConfigValue(OidcConfiguration.ALLOW_USERS_TO_SIGN_UP, "false");
    assertThat(underTest.allowUsersToSignUp()).isFalse();
  }

  @Test
  public void group_sync() {
    mockConfigValue(OidcConfiguration.GROUPS_SYNC, "true");
    assertThat(underTest.syncGroups()).isTrue();

    mockConfigValue(OidcConfiguration.GROUPS_SYNC, "false");
    assertThat(underTest.syncGroups()).isFalse();
  }

  @Test
  public void group_sync_claim_name() {
    assertThat(underTest.syncGroupsClaimName()).isEqualTo("groups");
    mockConfigValue(OidcConfiguration.GROUPS_SYNC_CLAIM_NAME, "test");
    assertThat(underTest.syncGroupsClaimName()).isEqualTo("test");
  }

  @Test
  public void scopes() {
    mockConfigValue(OidcConfiguration.SCOPES, "openid");
    assertThat(underTest.scopes()).isEqualTo("openid");
  }

  @Test
  public void icon_path() {
    mockConfigValue(OidcConfiguration.ICON_PATH, "http://mydomain.com/myicon.png");
    assertThat(underTest.iconPath()).isEqualTo("http://mydomain.com/myicon.png");
  }

  @Test
  public void background_color() {
    mockConfigValue(OidcConfiguration.BACKGROUND_COLOR, "#123456");
    assertThat(underTest.backgroundColor()).isEqualTo("#123456");
  }

  @Test
  public void login_button_text() {
    mockConfigValue(OidcConfiguration.LOGIN_BUTTON_TEXT, "My Company Single-Sign-On");
    assertThat(underTest.loginButtonText()).isEqualTo("My Company Single-Sign-On");
  }

  @Test
  public void definitions() {
    assertThat(OidcConfiguration.definitions()).hasSize(15);
  }

  @Test
  public void with_base_url() {
    mockConfigValue(CoreProperties.SERVER_BASE_URL, SONAR_URL);
    assertThat(underTest.getBaseUrl()).isEqualTo(SONAR_URL);
  }

  @Test
  public void without_base_url() {
    mockConfigValue(CoreProperties.SERVER_BASE_URL, (String) null);
    assertThat(underTest.getBaseUrl()).isEmpty();
  }

  @Test
  public void with_context() {
    mockConfigValue("sonar.web.context", "sonar");
    assertThat(underTest.getContextPath()).isEqualTo("sonar");
  }

}
