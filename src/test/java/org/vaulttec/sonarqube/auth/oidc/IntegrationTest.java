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

import com.nimbusds.common.contenttype.ContentType;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.server.http.HttpRequest;
import org.sonar.api.server.http.HttpResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.String.format;
import static java.net.URLEncoder.encode;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IntegrationTest extends AbstractOidcTest {

  @Rule
  public MockWebServer idp = new MockWebServer();
  private String idpUri = format("http://%s:%d", idp.getHostName(), idp.getPort());

  private OidcClient oidcClient;
  private UserIdentityFactory userIdentityFactory;
  private OidcIdentityProvider underTest;

  @Before
  public void init() {
    setSettings(true, idpUri);
    oidcClient = createSpyOidcClient();
    userIdentityFactory = new UserIdentityFactory(oidcConfig);
    underTest = new OidcIdentityProvider(oidcConfig, oidcClient, userIdentityFactory);
  }

  /**
   * First phase: SonarQube redirects browser to OpenID connect provider's
   * authentication form, requesting the minimal access rights ("scope") to get
   * user profile.
   */
  @Test
  public void redirect_browser_to_oidc_authentication_form() throws Exception {
    DumbInitContext context = new DumbInitContext("the-csrf-state");
    underTest.init(context);
    assertThat(context.redirectedTo).startsWith(idp.url("protocol/openid-connect/auth").toString())
        .contains("scope=" + encode("openid email profile", StandardCharsets.UTF_8.name()));
  }

  /**
   * Second phase: OpenID connect provider redirects browser to SonarQube at
   * /oauth/callback/oidc?code={the access code}. This SonarQube web service sends
   * access / ID token request to the OpenID connect provider.
   */
  @Test
  public void callback_on_successful_authentication() throws IOException, InterruptedException {
    idp.enqueue(newSuccessfulAccessTokenResponse());
    HttpRequest request = newAuthenticationRequest();
    DumbCallbackContext callbackContext = new DumbCallbackContext(request);
    underTest.callback(callbackContext);

    // generate an unique login by default (suffixed by "@oidc"), instead of copying
    // oidc login as-this.
    assertThat(callbackContext.userIdentity.getProviderLogin()).isEqualTo("john.doo");
    assertThat(callbackContext.userIdentity.getName()).isEqualTo("John Doo");
    assertThat(callbackContext.userIdentity.getEmail()).isEqualTo("john.doo@acme.com");
    assertThat(callbackContext.userIdentity.getGroups()).hasSize(2);
    assertThat(callbackContext.redirectedToRequestedPage.get()).isTrue();

    // verify the requests sent to OpenID Connect provider
    RecordedRequest accessTokenRequest = idp.takeRequest();
    assertThat(accessTokenRequest.getPath()).startsWith("/protocol/openid-connect/token");
  }

  /**
   * Second phase: OpenID connect provider redirects browser to SonarQube at
   * /oauth/callback/oidc?code={the access code}. This SonarQube web service sends
   * access / ID token request to the OpenID connect provider. Due to missing user
   * profile information in the ID token an additional request is necessary.
   */
  @Test
  public void callback_on_successful_authentication_with_additional_user_info_request()
      throws IOException, InterruptedException {
    idp.enqueue(newSuccessfulAccessTokenResponseWithoutUserInfo());
    idp.enqueue(newUserInfoResponse());
    HttpRequest request = newAuthenticationRequest();
    DumbCallbackContext callbackContext = new DumbCallbackContext(request);
    underTest.callback(callbackContext);

    // generate an unique login by default (suffixed by "@oidc"), instead of copying
    // oidc login as-this.
    assertThat(callbackContext.userIdentity.getProviderLogin()).isEqualTo("john.doo");
    assertThat(callbackContext.userIdentity.getName()).isEqualTo("John Doo");
    assertThat(callbackContext.userIdentity.getEmail()).isEqualTo("john.doo@acme.com");
    assertThat(callbackContext.userIdentity.getGroups()).hasSize(2);
    assertThat(callbackContext.redirectedToRequestedPage.get()).isTrue();

    // verify the requests sent to OpenID Connect provider
    RecordedRequest accessTokenRequest = idp.takeRequest();
    assertThat(accessTokenRequest.getPath()).startsWith("/protocol/openid-connect/token");
  }

  /**
   * Second phase: OpenID connect provider redirects browser to SonarQube at
   * /oauth/callback/oidc?code={the access code}. This SonarQube web service sends
   * access / ID token request to the OpenID connect provider. Due to missing user
   * profile information in the ID token an additional request is necessary.
   */
  @Test
  public void callback_on_successful_authentication_with_additional_user_info_request_for_groups()
      throws IOException, InterruptedException {
    idp.enqueue(newSuccessfulAccessTokenResponseWithoutGroupsClaim());
    idp.enqueue(newUserInfoResponse());
    HttpRequest request = newAuthenticationRequest();
    DumbCallbackContext callbackContext = new DumbCallbackContext(request);
    underTest.callback(callbackContext);

    // generate an unique login by default (suffixed by "@oidc"), instead of copying
    // oidc login as-this.
    assertThat(callbackContext.userIdentity.getProviderLogin()).isEqualTo("john.doo");
    assertThat(callbackContext.userIdentity.getName()).isEqualTo("John Doo");
    assertThat(callbackContext.userIdentity.getEmail()).isEqualTo("john.doo@acme.com");
    assertThat(callbackContext.userIdentity.getGroups()).hasSize(2);
    assertThat(callbackContext.redirectedToRequestedPage.get()).isTrue();

    // verify the requests sent to OpenID Connect provider
    RecordedRequest accessTokenRequest = idp.takeRequest();
    assertThat(accessTokenRequest.getPath()).startsWith("/protocol/openid-connect/token");
  }

  @Test
  public void callback_throws_ISE_if_error_when_requesting_id_token() throws InterruptedException {
    idp.enqueue(new MockResponse().addHeader("Content-Type", ContentType.APPLICATION_JSON).setResponseCode(500)
        .setBody("{\"error\":\"invalid_grant\",\"error_description\":\"Invalid resource owner credentials\"}"));
    DumbCallbackContext callbackContext = new DumbCallbackContext(newAuthenticationRequest());

    try {
      underTest.callback(callbackContext);
      failBecauseExceptionWasNotThrown(IllegalStateException.class);
    } catch (IllegalStateException e) {
      assertEquals("Token request failed: {\"error_description\":\"Invalid resource owner credentials\","
          + "\"error\":\"invalid_grant\"}", e.getMessage());
    }
    assertThat(callbackContext.csrfStateVerified.get()).isTrue();
    assertThat(callbackContext.userIdentity).isNull();
    assertThat(callbackContext.redirectedToRequestedPage.get()).isFalse();

    // verify the requests sent to OpenID Connect provider
    RecordedRequest accessTokenRequest = idp.takeRequest();
    assertThat(accessTokenRequest.getPath()).startsWith("/protocol/openid-connect/token");
  }

  private static HttpRequest newAuthenticationRequest() {
    HttpRequest request = mock(HttpRequest.class);
    when(request.getMethod()).thenReturn("GET");
    when(request.getRequestURL()).thenReturn("http://:0");
    when(request.getHeaderNames()).thenReturn(Collections.emptyEnumeration());
    when(request.getQueryString()).thenReturn("state=" + STATE + "&code=" + VALID_CODE);
    return request;
  }

  private static MockResponse newSuccessfulAccessTokenResponse() {
    return new MockResponse().setHeader("content-type", "application/json").setBody(
        "{\"access_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3djY4UzUybDZTWVUxNGFfd0N3VElJT01WV1d1RXVXUFNBcERjYXo5Rnd3In0.eyJqdGkiOiIzMWNkOWM3YS05YTM3LTRiOTktOTViMC1jNzJlNGYzNGY4ODEiLCJleHAiOjE1MTQzMDcwNTQsIm5iZiI6MCwiaWF0IjoxNTE0MzA2NzU0LCJpc3MiOiJodHRwOi8vbWFjYm9vay1wcm8uZnJpdHouYm94OjgwODAvYXV0aC9yZWFsbXMvc3NvIiwiYXVkIjoic29uYXJxdWJlIiwic3ViIjoiYWZhYmE1OTItYWM4NS00Y2YxLThlYzYtMDA1OGQxNTdmODgyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoic29uYXJxdWJlIiwiYXV0aF90aW1lIjoxNTE0MzA2NzU0LCJzZXNzaW9uX3N0YXRlIjoiYWE2N2NjNjktN2EwNi00N2QxLWJhMDAtNjk2NDZlNjBiOGJlIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbWFjYm9vay1wcm8uZnJpdHouYm94OjgwODIvIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJKb2huIERvbyIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9vIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvbyIsImVtYWlsIjoiam9obi5kb29AYWNtZS5jb20ifQ.YElE-QodhPc8cUGo3jhT-phkmS3k_fHHDXhVm54m4wIZKDFeOnJD0spYkcODrIrOc04ibbinKJERtiBRxBF0P4RQq7NY08rgxFqt1STNrDb9tr4N_qEDXQ_66OUJKQIMd1L5yB5dzj73XAR1LRkhZSfVmDEGyE6A0x5rxgAeWCXUqMWOOq8Vq0ksdXiXeSdyg2n1XWU2j-uf6GB6mMtLXA0NddzQMOxPyhAKCGJRDJTwwb0fXzPeOVOvXO918rahsJ4iFn7wDnV2vaFBu37SNID7Iqmx3D_ptS2QrCdItg6nnK589BpcQMamTHINIQbkF-7LQH-U_yVJyEkOVrPzoQ\","
            + "\"refresh_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3djY4UzUybDZTWVUxNGFfd0N3VElJT01WV1d1RXVXUFNBcERjYXo5Rnd3In0.eyJqdGkiOiI3NzJkZTg1ZS1jNjcxLTQ0NDgtYTAwYS04ZjVkZTRkOWNlZTYiLCJleHAiOjE1MTQzMDg1NTQsIm5iZiI6MCwiaWF0IjoxNTE0MzA2NzU0LCJpc3MiOiJodHRwOi8vbWFjYm9vay1wcm8uZnJpdHouYm94OjgwODAvYXV0aC9yZWFsbXMvc3NvIiwiYXVkIjoic29uYXJxdWJlIiwic3ViIjoiYWZhYmE1OTItYWM4NS00Y2YxLThlYzYtMDA1OGQxNTdmODgyIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6InNvbmFycXViZSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImFhNjdjYzY5LTdhMDYtNDdkMS1iYTAwLTY5NjQ2ZTYwYjhiZSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.Sqg5bqxEkpcg6r66fPW1X-RZvOMeKxHLl4Xk7S4BzGMiDNE8FlkbxW0JWUEm35oI3D0TVYv0B_MSFVc6mENBQeW3boJAtKUUCQy2FYKU4jta3KF-WLwKoTeU22ry-ZhRuJlydK-t0U3tB2ldWXTTfVI1qjHADIFt2RSggwhpU4iwZJiihxhk2KbVngClrNJ6Bk2olM276gopKzz9GN3erLXHZRtnzS3ZpyPvFzCoatP8v-FItAk01izToLbjyCjjicCBZfiMCw1_T0Zc1yz7l2kS0AE2kRBSDo58NggVL8yyXPhaLibigxYcIdawl9FpE3w5aiEquCH5WuQv5tt6LA\","
            + "\"scope\":\"\","
            + "\"id_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIwYzdkNDQ0Yy1iM2MxLTQzM2YtODQ1OC1iYzRlYmQ4YjM4MGIiLCJleHAiOjE1MTgyODIxMjksIm5iZiI6MCwiaWF0IjoxNTE0MzA2NzU0LCJpc3MiOiJodHRwOi8vbWFjYm9vay1wcm8uZnJpdHouYm94OjgwODAvYXV0aC9yZWFsbXMvc3NvIiwiYXVkIjoic29uYXJxdWJlIiwic3ViIjoiYWZhYmE1OTItYWM4NS00Y2YxLThlYzYtMDA1OGQxNTdmODgyIiwidHlwIjoiSUQiLCJhenAiOiJzb25hcnF1YmUiLCJhdXRoX3RpbWUiOjE1MTQzMDY3NTQsInNlc3Npb25fc3RhdGUiOiJhYTY3Y2M2OS03YTA2LTQ3ZDEtYmEwMC02OTY0NmU2MGI4YmUiLCJhY3IiOiIxIiwibmFtZSI6IkpvaG4gRG9vIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiam9obi5kb28iLCJnaXZlbl9uYW1lIjoiSm9obiIsImZhbWlseV9uYW1lIjoiRG9vIiwiZW1haWwiOiJqb2huLmRvb0BhY21lLmNvbSIsIm15R3JvdXBzIjpbImdyb3VwMSIsImdyb3VwMiJdfQ.9fBXCl1kYzaRVpkKY_sk6QTVfDcww7n0X7LD2srOLC0\","
            + "\"token_type\":\"Bearer\",\"expires_in\":300}");
  }

  private static MockResponse newSuccessfulAccessTokenResponseWithoutGroupsClaim() {
    return new MockResponse().setHeader("content-type", "application/json").setBody(
        "{\"access_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3djY4UzUybDZTWVUxNGFfd0N3VElJT01WV1d1RXVXUFNBcERjYXo5Rnd3In0.eyJqdGkiOiIzMWNkOWM3YS05YTM3LTRiOTktOTViMC1jNzJlNGYzNGY4ODEiLCJleHAiOjE1MTQzMDcwNTQsIm5iZiI6MCwiaWF0IjoxNTE0MzA2NzU0LCJpc3MiOiJodHRwOi8vbWFjYm9vay1wcm8uZnJpdHouYm94OjgwODAvYXV0aC9yZWFsbXMvc3NvIiwiYXVkIjoic29uYXJxdWJlIiwic3ViIjoiYWZhYmE1OTItYWM4NS00Y2YxLThlYzYtMDA1OGQxNTdmODgyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoic29uYXJxdWJlIiwiYXV0aF90aW1lIjoxNTE0MzA2NzU0LCJzZXNzaW9uX3N0YXRlIjoiYWE2N2NjNjktN2EwNi00N2QxLWJhMDAtNjk2NDZlNjBiOGJlIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbWFjYm9vay1wcm8uZnJpdHouYm94OjgwODIvIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sIm5hbWUiOiJKb2huIERvbyIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9vIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvbyIsImVtYWlsIjoiam9obi5kb29AYWNtZS5jb20ifQ.YElE-QodhPc8cUGo3jhT-phkmS3k_fHHDXhVm54m4wIZKDFeOnJD0spYkcODrIrOc04ibbinKJERtiBRxBF0P4RQq7NY08rgxFqt1STNrDb9tr4N_qEDXQ_66OUJKQIMd1L5yB5dzj73XAR1LRkhZSfVmDEGyE6A0x5rxgAeWCXUqMWOOq8Vq0ksdXiXeSdyg2n1XWU2j-uf6GB6mMtLXA0NddzQMOxPyhAKCGJRDJTwwb0fXzPeOVOvXO918rahsJ4iFn7wDnV2vaFBu37SNID7Iqmx3D_ptS2QrCdItg6nnK589BpcQMamTHINIQbkF-7LQH-U_yVJyEkOVrPzoQ\","
            + "\"refresh_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3djY4UzUybDZTWVUxNGFfd0N3VElJT01WV1d1RXVXUFNBcERjYXo5Rnd3In0.eyJqdGkiOiI3NzJkZTg1ZS1jNjcxLTQ0NDgtYTAwYS04ZjVkZTRkOWNlZTYiLCJleHAiOjE1MTQzMDg1NTQsIm5iZiI6MCwiaWF0IjoxNTE0MzA2NzU0LCJpc3MiOiJodHRwOi8vbWFjYm9vay1wcm8uZnJpdHouYm94OjgwODAvYXV0aC9yZWFsbXMvc3NvIiwiYXVkIjoic29uYXJxdWJlIiwic3ViIjoiYWZhYmE1OTItYWM4NS00Y2YxLThlYzYtMDA1OGQxNTdmODgyIiwidHlwIjoiUmVmcmVzaCIsImF6cCI6InNvbmFycXViZSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImFhNjdjYzY5LTdhMDYtNDdkMS1iYTAwLTY5NjQ2ZTYwYjhiZSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.Sqg5bqxEkpcg6r66fPW1X-RZvOMeKxHLl4Xk7S4BzGMiDNE8FlkbxW0JWUEm35oI3D0TVYv0B_MSFVc6mENBQeW3boJAtKUUCQy2FYKU4jta3KF-WLwKoTeU22ry-ZhRuJlydK-t0U3tB2ldWXTTfVI1qjHADIFt2RSggwhpU4iwZJiihxhk2KbVngClrNJ6Bk2olM276gopKzz9GN3erLXHZRtnzS3ZpyPvFzCoatP8v-FItAk01izToLbjyCjjicCBZfiMCw1_T0Zc1yz7l2kS0AE2kRBSDo58NggVL8yyXPhaLibigxYcIdawl9FpE3w5aiEquCH5WuQv5tt6LA\","
            + "\"scope\":\"\","
            + "\"id_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIwYzdkNDQ0Yy1iM2MxLTQzM2YtODQ1OC1iYzRlYmQ4YjM4MGIiLCJleHAiOjE1ODg2MTE4NTEsIm5iZiI6MCwiaWF0IjoxNTE0MzA2NzU0LCJpc3MiOiJodHRwOi8vbWFjYm9vay1wcm8uZnJpdHouYm94OjgwODAvYXV0aC9yZWFsbXMvc3NvIiwiYXVkIjoic29uYXJxdWJlIiwic3ViIjoiYWZhYmE1OTItYWM4NS00Y2YxLThlYzYtMDA1OGQxNTdmODgyIiwidHlwIjoiSUQiLCJhenAiOiJzb25hcnF1YmUiLCJhdXRoX3RpbWUiOjE1MTQzMDY3NTQsInNlc3Npb25fc3RhdGUiOiJhYTY3Y2M2OS03YTA2LTQ3ZDEtYmEwMC02OTY0NmU2MGI4YmUiLCJhY3IiOiIxIiwibmFtZSI6IkpvaG4gRG9vIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiam9obi5kb28iLCJnaXZlbl9uYW1lIjoiSm9obiIsImZhbWlseV9uYW1lIjoiRG9vIiwiZW1haWwiOiJqb2huLmRvb0BhY21lLmNvbSJ9.Gog53MNSmASNn5E2268vvdPIk7C-EnxftzTKTm5_AlM\","
            + "\"token_type\":\"Bearer\",\"expires_in\":300}");
  }

  private static MockResponse newSuccessfulAccessTokenResponseWithoutUserInfo() {
    return new MockResponse().setHeader("content-type", "application/json").setBody(
        "{\"id_token\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJlNjVjOTYwNy1mZDRlLTRiY2QtOTdiMS1jYTA1NzYxNjU5MGUiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaHViIiwiYXVkIjpbIjYwZGNhY2FmLThhOTQtNDE3Ny1iMmYyLTEzNDg0NjNmODhjZSJdLCJleHAiOjEuNTIzNTcyMTY3NTYxRTksImlhdCI6MS41MTU3OTYxNjc1OTdFOSwiYXV0aF90aW1lIjoxLjUxNTc5NjE2NzU2MUU5fQ.o_h3f6QK--p1Ru8pUquoLpvB1vdBCorUfdq_I8J_yBbjyPS4LUP9-e_xkXtql6yOSh9AewNUb7PSKnJOq-TlMMMlOr-Or676i1wT0hGQb2aKnzzFu7VYQOep8_6t-AQSXRhckaR5NIJnF6oxFWdTwhizcenO_Osf12R-PQOyQsA\","
            + "\"access_token\":\"invalid\"," + "\"token_type\":\"Bearer\"," + "\"expires_in\":3600,"
            + "\"scope\":\"0-0-0-0-0\"}");
  }

  private static MockResponse newUserInfoResponse() {
    return new MockResponse().setHeader("content-type", "application/json")
        .setBody("{\"sub\":\"e65c9607-fd4e-4bcd-97b1-ca057616590e\","
            + "\"name\":\"John Doo\",\"preferred_username\":\"john.doo\","
            + "\"profile\":\"http://localhost:8080/hub/users/e65c9607-fd4e-4bcd-97b1-ca057616590e\","
            + "\"email\":\"john.doo@acme.com\",\"email_verified\":true,\"myGroups\":[\"group1\",\"group2\"]}");
  }

  private static class DumbCallbackContext implements OAuth2IdentityProvider.CallbackContext {
    final HttpRequest request;
    final AtomicBoolean csrfStateVerified = new AtomicBoolean(false);
    final AtomicBoolean redirectedToRequestedPage = new AtomicBoolean(false);
    UserIdentity userIdentity = null;

    public DumbCallbackContext(HttpRequest request) {
      this.request = request;
    }

    @Override
    public void verifyCsrfState() {
      this.csrfStateVerified.set(true);
    }

    @Override
    public void redirectToRequestedPage() {
      redirectedToRequestedPage.set(true);
    }

    @Override
    public void authenticate(UserIdentity userIdentity) {
      this.userIdentity = userIdentity;
    }

    @Override
    public String getCallbackUrl() {
      return CALLBACK_URL;
    }

    @Override
    public HttpRequest getHttpRequest() {
      return request;
    }

    @Override
    public HttpResponse getHttpResponse() {
      throw new UnsupportedOperationException("not used");
    }

    @Override
    public void verifyCsrfState(String parameterName) {
    }
  }

  private static class DumbInitContext implements OAuth2IdentityProvider.InitContext {
    String redirectedTo = null;
    private final String generatedCsrfState;

    public DumbInitContext(String generatedCsrfState) {
      this.generatedCsrfState = generatedCsrfState;
    }

    @Override
    public String generateCsrfState() {
      return generatedCsrfState;
    }

    @Override
    public void redirectTo(String url) {
      this.redirectedTo = url;
    }

    @Override
    public String getCallbackUrl() {
      return CALLBACK_URL;
    }

    @Override
    public HttpRequest getHttpRequest() {
      return null;
    }

    @Override
    public HttpResponse getHttpResponse() {
      return null;
    }
  }

}
