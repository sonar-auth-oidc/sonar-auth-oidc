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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest.Builder;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import org.sonar.api.server.ServerSide;
import org.sonar.api.server.http.HttpRequest;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

@ServerSide
public class OidcClient {

  private static final Logger LOGGER = Loggers.get(OidcClient.class);

  private static final ResponseType RESPONSE_TYPE = new ResponseType(Value.CODE);
  private final OidcConfiguration config;

  public OidcClient(OidcConfiguration config) {
    this.config = config;
  }

  public AuthenticationRequest createAuthenticationRequest(String callbackUrl, String state) {
    AuthenticationRequest request;
    LOGGER.debug("Creating authentication request");
    OIDCProviderMetadata providerMetadata = getProviderMetadata();
    try {
      Builder builder = new AuthenticationRequest.Builder(RESPONSE_TYPE, getScope(), getClientId(),
          new URI(callbackUrl));
      request = builder.endpointURI(providerMetadata.getAuthorizationEndpointURI()).state(State.parse(state)).build();
    } catch (URISyntaxException e) {
      throw new IllegalStateException("Creating new authentication request failed", e);
    }
    LOGGER.debug("Authentication request URI: {}", request.toURI());
    return request;
  }

  public AuthorizationCode getAuthorizationCode(HttpRequest callbackRequest) {
    LOGGER.debug("Retrieving authorization code from callback request's query parameters: {}",
        callbackRequest.getQueryString());
    AuthenticationResponse authResponse;
    try {
      URI uri = new URI(callbackRequest.getRequestURL());

      Map<String, List<String>> queryParams = new HashMap<>();
      String queryString = callbackRequest.getQueryString();
      if (queryString != null && !queryString.isEmpty() ) {
        String[] pairs = queryString.split("&");
        for (String pair: pairs) {
          int idx = pair.indexOf("=");
          if (idx > 0) {
            String key = URLDecoder.decode(pair.substring(0,idx), "UTF-8");
            String value = URLDecoder.decode(pair.substring(idx + 1), "UTF-8");
            queryParams.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
          }
        }
      }
     authResponse = AuthenticationResponseParser.parse(uri, queryParams);
    } catch (ParseException | URISyntaxException | UnsupportedEncodingException e) {
      throw new IllegalStateException("Error while processing callback request", e);
    }

    if (authResponse instanceof AuthenticationErrorResponse) {
      ErrorObject error = ((AuthenticationErrorResponse) authResponse).getErrorObject();
      throw new IllegalStateException("Authentication request failed: " + error.toJSONObject());
    }

    AuthorizationCode authorizationCode = ((AuthenticationSuccessResponse) authResponse).getAuthorizationCode();
    LOGGER.debug("Authorization code: {}", authorizationCode.getValue());
    return authorizationCode;
  }

  public UserInfo getUserInfo(AuthorizationCode authorizationCode, String callbackUrl) {
    LOGGER.debug("Getting user info for authorization code");
    OIDCProviderMetadata providerMetadata = getProviderMetadata();
    OIDCTokens oidcTokens = getOidcTokens(authorizationCode, callbackUrl, providerMetadata);

    UserInfo userInfo;
    try {
      userInfo = new UserInfo(oidcTokens.getIDToken().getJWTClaimsSet());
    } catch (java.text.ParseException e) {
      throw new IllegalStateException("Parsing ID token failed", e);
    }
    if (((userInfo.getName() == null) && (userInfo.getPreferredUsername() == null))
        || (config.syncGroups() && userInfo.getClaim(config.syncGroupsClaimName()) == null)) {
      UserInfoResponse userInfoResponse = getUserInfoResponse(providerMetadata.getUserInfoEndpointURI(),
          oidcTokens.getBearerAccessToken());
      if (userInfoResponse instanceof UserInfoErrorResponse) {
        ErrorObject errorObject = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
        if (errorObject == null || errorObject.getCode() == null) {
          throw new IllegalStateException("UserInfo request failed: No error code returned "
              + "(identity provider not reachable - check network proxy setting 'http.nonProxyHosts' in 'sonar.properties')");
        } else {
          throw new IllegalStateException("UserInfo request failed: " + errorObject.toJSONObject());
        }
      }
      userInfo = ((UserInfoSuccessResponse) userInfoResponse).getUserInfo();
    }

    LOGGER.debug("User info: {}", userInfo.toJSONObject());
    return userInfo;
  }

  private OIDCTokens getOidcTokens(AuthorizationCode authorizationCode, String callbackUrl, OIDCProviderMetadata providerMetadata) {
    LOGGER.debug("Retrieving OIDC tokens with user info claims set from {}", providerMetadata.getTokenEndpointURI());
    TokenResponse tokenResponse = getTokenResponse(providerMetadata.getTokenEndpointURI(), authorizationCode,
        callbackUrl);
    if (tokenResponse instanceof TokenErrorResponse) {
      ErrorObject errorObject = ((TokenErrorResponse) tokenResponse).getErrorObject();
      if (errorObject == null || errorObject.getCode() == null) {
        throw new IllegalStateException("Token request failed: No error code returned "
            + "(identity provider not reachable - check network proxy setting 'http.nonProxyHosts' in 'sonar.properties')");
      } else {
        throw new IllegalStateException("Token request failed: " + errorObject.toJSONObject());
      }
    }
    OIDCTokens oidcTokens = ((OIDCTokenResponse) tokenResponse).getOIDCTokens();
    if (isIdTokenSigned()) {
      validateIdToken(providerMetadata.getIssuer(), providerMetadata.getJWKSetURI(), oidcTokens.getIDToken());
    }
    return oidcTokens;
  }

  protected TokenResponse getTokenResponse(URI tokenEndpointURI, AuthorizationCode authorizationCode,
      String callbackUrl) {
    try {
      TokenRequest request = new TokenRequest(tokenEndpointURI, new ClientSecretBasic(getClientId(), getClientSecret()),
          new AuthorizationCodeGrant(authorizationCode, new URI(callbackUrl)));
      HTTPResponse response = request.toHTTPRequest().send();
      LOGGER.debug("Token response content: {}", response.getContent());
      return OIDCTokenResponseParser.parse(response);
    } catch (URISyntaxException | ParseException e) {
      throw new IllegalStateException("Retrieving access token failed", e);
    } catch (IOException e) {
      throw new IllegalStateException("Retrieving access token failed: "
          + "Identity provider not reachable - check network proxy setting 'http.nonProxyHosts' in 'sonar.properties'");
    }
  }

  private void validateIdToken(Issuer issuer, URI jwkSetURI, JWT idToken) {
    LOGGER.debug("Validating ID token with {} and key set from from {}", getIdTokenSignAlgorithm(), jwkSetURI);
    try {
      IDTokenValidator validator = createValidator(issuer, jwkSetURI.toURL());
      validator.validate(idToken, null);
    } catch (MalformedURLException e) {
      throw new IllegalStateException("Invalid JWK set URL", e);
    } catch (BadJOSEException e) {
      throw new IllegalStateException("Invalid ID token", e);
    } catch (JOSEException e) {
      throw new IllegalStateException("Validating ID token failed", e);
    }
  }

  protected IDTokenValidator createValidator(Issuer issuer, URL jwkSetUrl) {
    return new IDTokenValidator(issuer, getClientId(), getIdTokenSignAlgorithm(), jwkSetUrl);
  }

  protected UserInfoResponse getUserInfoResponse(URI userInfoEndpointURI, BearerAccessToken accessToken) {
    LOGGER.debug("Retrieving user info from {}", userInfoEndpointURI);
    try {
      UserInfoRequest request = new UserInfoRequest(userInfoEndpointURI, accessToken);
      HTTPResponse response = request.toHTTPRequest().send();
      LOGGER.debug("UserInfo response content: {}", response.getContent());
      return UserInfoResponse.parse(response);
    } catch (ParseException e) {
      throw new IllegalStateException("Retrieving user information failed", e);
    } catch (IOException e) {
      throw new IllegalStateException("Retrieving user information failed: "
          + "Identity provider not reachable - check network proxy setting 'http.nonProxyHosts' in 'sonar.properties'");
    }
  }

  protected OIDCProviderMetadata getProviderMetadata() {
    LOGGER.debug("Retrieving provider metadata from {}", config.issuerUri());
    try {
      return OIDCProviderMetadata.resolve(new Issuer(config.issuerUri()));
    } catch (IOException | GeneralException e) {
      if (e instanceof GeneralException && e.getMessage().contains("issuer doesn't match")) {
        throw new IllegalStateException("Retrieving OpenID Connect provider metadata failed: " +
                "Issuer URL in provider metadata doesn't match the issuer URI specified in plugin configuration");
      } else {
        throw new IllegalStateException("Retrieving OpenID Connect provider metadata failed", e);
      }
    }
  }

  private Scope getScope() {
    return Scope.parse(config.scopes());
  }

  private ClientID getClientId() {
    return new ClientID(config.clientId());
  }

  private Secret getClientSecret() {
    String secret = config.clientSecret();
    return secret == null ? new Secret("") : new Secret(secret);
  }

  private boolean isIdTokenSigned() {
    return config.idTokenSignAlgorithm() != null;
  }

  private JWSAlgorithm getIdTokenSignAlgorithm() {
    String algorithmName = config.idTokenSignAlgorithm();
    return algorithmName == null ? null : new JWSAlgorithm(algorithmName);
  }

}
