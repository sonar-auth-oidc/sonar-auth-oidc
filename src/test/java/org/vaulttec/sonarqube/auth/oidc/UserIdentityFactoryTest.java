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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.Before;
import org.junit.Test;
import org.sonar.api.config.Configuration;
import org.sonar.api.config.PropertyDefinitions;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.utils.System2;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserIdentityFactoryTest {


  private Map<String, String> settings = new HashMap<>();
  private Configuration config = mock(Configuration.class);
  private UserIdentityFactory underTest = new UserIdentityFactory(new OidcConfiguration(config));

  @Before
  public void setup(){
    PropertyDefinitions definitions = new PropertyDefinitions(System2.INSTANCE, OidcConfiguration.definitions());
    when(config.get(any())).thenAnswer(invocation -> Optional.ofNullable(settings.get(invocation.getArgument(0))).or(() -> Optional.ofNullable(definitions.getDefaultValue(invocation.getArgument(0)))));
    when(config.getBoolean(any())).thenAnswer(invocation -> config.get(invocation.getArgument(0)).map(Boolean::parseBoolean));
  }

  @Test
  public void create_for_provider_strategy() {
    UserInfo userInfo = newUserInfo(false, false);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_PROVIDER_ID);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_unique_login_strategy() {
    UserInfo userInfo = newUserInfo(false, false);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_UNIQUE);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8@oidc");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_preferred_username_login_strategy() {
    UserInfo userInfo = newUserInfo(false, false);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_PREFERRED_USERNAME);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo("jdoo");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_email_login_strategy() {
    UserInfo userInfo = newUserInfo(false, false);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_EMAIL);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo(identity.getEmail());
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_custom_claim_strategy() {
    UserInfo userInfo = newUserInfo(false, false);
    userInfo.setClaim("upn", "johndoo");
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_CUSTOM_CLAIM);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo(userInfo.getClaim("upn"));
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void no_email() {
    UserInfo userInfo = newUserInfo(false, false);
    userInfo.setEmailAddress(null);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_PROVIDER_ID);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isNull();
  }

  @Test
  public void null_name_is_replaced_by_preferred_username() {
    UserInfo userInfo = newUserInfo(false, false);
    userInfo.setName(null);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getName()).isEqualTo("jdoo");
  }

  @Test
  public void throw_ISE_if_strategy_is_not_supported() {
    UserInfo userInfo = newUserInfo(false, false);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, "xxx");

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> underTest.create(userInfo));
    assertTrue(exception.getMessage().contains("Login strategy not supported: xxx"));
  }

  @Test
  public void throw_ISE_if_missing_preferred_username() {
    UserInfo userInfo = newUserInfo(false, false);
    userInfo.setPreferredUsername(null);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_PREFERRED_USERNAME);

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> underTest.create(userInfo));
    assertTrue(exception.getMessage().startsWith("Claim 'preferred_username' is missing in user info"));
  }

  @Test
  public void throw_ISE_if_missing_email() {
    UserInfo userInfo = newUserInfo(false, false);
    userInfo.setEmailAddress(null);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_EMAIL);

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> underTest.create(userInfo));
    assertTrue(exception.getMessage().startsWith("Claim 'email' is missing in user info"));
  }

  @Test
  public void throw_ISE_if_missing_name_and_preferred_username() {
    UserInfo userInfo = newUserInfo(false, false);
    userInfo.setName(null);
    userInfo.setPreferredUsername(null);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_UNIQUE);

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> underTest.create(userInfo));
    assertTrue(exception.getMessage().startsWith("Claims 'name' and 'preferred_username' are missing in user info"));
  }

  @Test
  public void throw_ISE_if_missing_custom_claim() {
    UserInfo userInfo = newUserInfo(false, false);
    settings.put(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_CUSTOM_CLAIM);

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> underTest.create(userInfo));
    assertTrue(exception.getMessage().startsWith("Custom claim 'upn' is missing in user info"));
  }

  @Test
  public void create_with_synched_multiple_groups_as_list() {
    UserInfo userInfo = newUserInfo(false, false);
    settings.put(OidcConfiguration.GROUPS_SYNC, "true");

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getGroups()).containsAll(Arrays.asList("admins", "internal"));
  }

  @Test
  public void create_with_synched_multiple_groups_as_string() {
    UserInfo userInfo = newUserInfo(false, true);
    settings.put(OidcConfiguration.GROUPS_SYNC, "true");

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getGroups()).containsAll(Arrays.asList("admins", "internal"));
  }

  @Test
  public void create_with_synched_single_group_as_list() {
    UserInfo userInfo = newUserInfo(true, false);
    settings.put(OidcConfiguration.GROUPS_SYNC, "true");
    settings.put(OidcConfiguration.GROUPS_SYNC_CLAIM_NAME, "group");

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getGroups()).containsExactly("admins");
  }

  @Test
  public void create_with_synched_single_group_as_string() {
    UserInfo userInfo = newUserInfo(true, true);
    settings.put(OidcConfiguration.GROUPS_SYNC, "true");
    settings.put(OidcConfiguration.GROUPS_SYNC_CLAIM_NAME, "group");

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getGroups()).containsExactly("admins");
  }

  @Test
  public void create_with_synched_groups_invalid_groups_claim_name() {
    UserInfo userInfo = newUserInfo(false, false);
    settings.put(OidcConfiguration.GROUPS_SYNC, "true");
    settings.put(OidcConfiguration.GROUPS_SYNC_CLAIM_NAME, "invalid");

    IllegalStateException exception = assertThrows(IllegalStateException.class, () -> underTest.create(userInfo));
    assertTrue(exception.getMessage().startsWith("Groups claim 'invalid' is missing in user info"));
  }

  private UserInfo newUserInfo(boolean singleGroup, boolean string) {
    try {
      return UserInfo.parse("{\"sub\":\"8f63a486-6699-4f25-beef-118dd240bef8\"," +
          (singleGroup ?
              (string ? "\"group\":\"admins\"," : "\"group\":[\"admins\"],") :
              (string ? "\"groups\":\"admins, internal\"," : "\"groups\":[\"admins\",\"internal\"],"))
          + "\"iss\":\"http://localhost/auth/realms/sso\",\"typ\":\"ID\",\"preferred_username\":\"jdoo\","
          + "\"given_name\":\"John\",\"aud\":\"sonarqube\",\"acr\":\"1\",\"nbf\":0,\"azp\":\"sonarqube\","
          + "\"auth_time\":1514307002,\"name\":\"John Doo\",\"exp\":1514307302,"
          + "\"session_state\":\"f57b7a35-0de4-4ac1-8d8e-a93fc8e65cb2\",\"iat\":1514307002,"
          + "\"family_name\":\"Doo\",\"jti\":\"c4a1a958-21de-47b6-b860-d0417519de00\","
          + "\"email\":\"john.doo@acme.com\"}");
    } catch (ParseException e) {
      // ignore
    }
    return null;
  }

}
