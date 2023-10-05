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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.vaulttec.sonarqube.auth.oidc.OidcConfiguration.LOGIN_STRATEGY_DEFAULT_VALUE;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import org.sonar.api.config.internal.MapSettings;

public abstract class AbstractOidcTest {

  public static final String ISSUER_URI = "https://oidc.org";
  public static final String CALLBACK_URL = "http://localhost/callback";
  public static final String STATE = "state";
  public static final String VALID_CODE = "valid_code";

  protected MapSettings settings = new MapSettings();
  protected OidcConfiguration config = new OidcConfiguration(settings.asConfig());

  protected void setSettings(boolean enabled) {
    setSettings(enabled, ISSUER_URI);
  }

  protected void setSettings(boolean enabled, String issuerUri) {
    if (enabled) {
      settings.setProperty(OidcConfiguration.ENABLED, true);
      settings.setProperty(OidcConfiguration.ISSUER_URI, issuerUri);
      settings.setProperty(OidcConfiguration.CLIENT_ID, "id");
      settings.setProperty(OidcConfiguration.CLIENT_SECRET, "secret");
      settings.setProperty(OidcConfiguration.ID_TOKEN_SIG_ALG, "RS256");
      settings.setProperty(OidcConfiguration.LOGIN_STRATEGY, LOGIN_STRATEGY_DEFAULT_VALUE);
      settings.setProperty(OidcConfiguration.GROUPS_SYNC, true);
      settings.setProperty(OidcConfiguration.GROUPS_SYNC_CLAIM_NAME, "myGroups");
      settings.setProperty(OidcConfiguration.SCOPES, "openid email profile");
    } else {
      settings.setProperty(OidcConfiguration.ENABLED, false);
    }
  }

  protected OIDCProviderMetadata getProviderMetadata(String issuerUri) {
    try {
      return OIDCProviderMetadata.parse("{\"issuer\":\"" + issuerUri + "\"," + "\"authorization_endpoint\":\""
          + issuerUri + "/protocol/openid-connect/auth" + "\"," + "\"token_endpoint\":\"" + issuerUri
          + "/protocol/openid-connect/token\"," + "\"userinfo_endpoint\":\"" + issuerUri
          + "/protocol/openid-connect/userinfo\"," + "\"jwks_uri\":\"" + issuerUri + "/protocol/openid-connect/certs\","
          + "\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"client_credentials\"],"
          + "\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],"
          + "\"subject_types_supported\":[\"public\",\"pairwise\"],"
          + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
          + "\"userinfo_signing_alg_values_supported\":[\"RS256\"],"
          + "\"request_object_signing_alg_values_supported\":[\"none\",\"RS256\"],"
          + "\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],"
          + "\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\"],"
          + "\"token_endpoint_auth_signing_alg_values_supported\":[\"RS256\"],"
          + "\"claims_supported\":[\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\"],"
          + "\"claim_types_supported\":[\"normal\"]," + "\"claims_parameter_supported\":false,"
          + "\"scopes_supported\":[\"openid\",\"offline_access\"]," + "\"request_parameter_supported\":true,"
          + "\"request_uri_parameter_supported\":true}");
    } catch (ParseException e) {
      throw new IllegalStateException("Invalid provider metadata", e);
    }
  }

  protected OidcClient createSpyOidcClient() {
    OidcClient client = spy(new OidcClient(config));
    doReturn(getProviderMetadata(config.issuerUri())).when(client).getProviderMetadata();
    doReturn(mock(IDTokenValidator.class)).when(client).createValidator(any(), any());
    return client;
  }

  protected OidcClient createSpyOidcClient2() {
    OidcClient client = spy(new OidcClient(config));
    doReturn(getProviderMetadata(config.issuerUri())).when(client).getProviderMetadata();
    return client;
  }

  protected OidcClient createSpyOidcClient3() {
    OidcClient client = spy(new OidcClient(config));
    return client;
  }


}
