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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.startsWith;

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.PropertyDefinitions;
import org.sonar.api.config.internal.MapSettings;
import org.sonar.api.server.authentication.UserIdentity;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public class UserIdentityFactoryTest {

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  MapSettings settings = new MapSettings(new PropertyDefinitions(OidcConfiguration.definitions()));
  UserIdentityFactory underTest = new UserIdentityFactory(new OidcConfiguration(settings.asConfig()));

  @Test
  public void create_for_provider_strategy() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_PROVIDER_ID);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_unique_login_strategy() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_UNIQUE);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8@oidc");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_preferred_username_login_strategy() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_PREFERRED_USERNAME);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo("jdoo");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_email_login_strategy() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_EMAIL);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo(identity.getEmail());
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void create_for_custom_claim_strategy() {
    UserInfo userInfo = newUserInfo();
    userInfo.setClaim("upn", "johndoo");
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_CUSTOM_CLAIM);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo(userInfo.getClaim("upn"));
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isEqualTo("john.doo@acme.com");
  }

  @Test
  public void no_email() {
    UserInfo userInfo = newUserInfo();
    userInfo.setEmailAddress(null);
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_PROVIDER_ID);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getProviderLogin()).isEqualTo("8f63a486-6699-4f25-beef-118dd240bef8");
    assertThat(identity.getName()).isEqualTo("John Doo");
    assertThat(identity.getEmail()).isNull();
  }

  @Test
  public void null_name_is_replaced_by_preferred_username() {
    UserInfo userInfo = newUserInfo();
    userInfo.setName(null);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getName()).isEqualTo("jdoo");
  }

  @Test
  public void throw_ISE_if_strategy_is_not_supported() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, "xxx");

    expectedException.expect(IllegalStateException.class);
    expectedException.expectMessage("Login strategy not supported: xxx");
    underTest.create(userInfo);
  }

  @Test
  public void throw_ISE_if_missing_preferred_username() {
    UserInfo userInfo = newUserInfo();
    userInfo.setPreferredUsername(null);
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_PREFERRED_USERNAME);

    expectedException.expect(IllegalStateException.class);
    expectedException.expectMessage(startsWith("Claim 'preferred_username' is missing in user info"));
    underTest.create(userInfo);
  }

  @Test
  public void throw_ISE_if_missing_email() {
    UserInfo userInfo = newUserInfo();
    userInfo.setEmailAddress(null);
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_EMAIL);

    expectedException.expect(IllegalStateException.class);
    expectedException.expectMessage(startsWith("Claim 'email' is missing in user info"));
    underTest.create(userInfo);
  }

  @Test
  public void throw_ISE_if_missing_name_and_preferred_username() {
    UserInfo userInfo = newUserInfo();
    userInfo.setName(null);
    userInfo.setPreferredUsername(null);
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_UNIQUE);

    expectedException.expect(IllegalStateException.class);
    expectedException.expectMessage(startsWith("Claims 'name' and 'preferred_username' are missing in user info"));
    underTest.create(userInfo);
  }

  @Test
  public void throw_ISE_if_missing_custom_claim() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, OidcConfiguration.LOGIN_STRATEGY_CUSTOM_CLAIM);

    expectedException.expect(IllegalStateException.class);
    expectedException.expectMessage(startsWith("Custom claim 'upn' is missing in user info"));
    underTest.create(userInfo);
  }

  @Test
  public void create_with_synched_groups() {
    UserInfo userInfo = newUserInfo();
    settings.setProperty("sonar.auth.oidc.groupsSync", true);

    UserIdentity identity = underTest.create(userInfo);
    assertThat(identity.getGroups()).containsAll(Arrays.asList("admins", "internal"));
  }

  private UserInfo newUserInfo() {
    UserInfo userInfo = null;
    try {
      return UserInfo.parse("{\"sub\":\"8f63a486-6699-4f25-beef-118dd240bef8\",\"groups\":[\"admins\",\"internal\"],"
          + "\"iss\":\"http://localhost/auth/realms/sso\",\"typ\":\"ID\",\"preferred_username\":\"jdoo\","
          + "\"given_name\":\"John\",\"aud\":\"sonarqube\",\"acr\":\"1\",\"nbf\":0,\"azp\":\"sonarqube\","
          + "\"auth_time\":1514307002,\"name\":\"John Doo\",\"exp\":1514307302,"
          + "\"session_state\":\"f57b7a35-0de4-4ac1-8d8e-a93fc8e65cb2\",\"iat\":1514307002,"
          + "\"family_name\":\"Doo\",\"jti\":\"c4a1a958-21de-47b6-b860-d0417519de00\","
          + "\"email\":\"john.doo@acme.com\"}");
    } catch (ParseException e) {
      // ignore
    }
    return userInfo;
  }

}
