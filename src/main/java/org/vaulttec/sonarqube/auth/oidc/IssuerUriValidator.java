/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2017 Torsten Juergeleit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.vaulttec.sonarqube.auth.oidc;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Validates issuer URIs before discovery calls.
 */
final class IssuerUriValidator {

  private IssuerUriValidator() {
  }

  static void validate(String issuerUri) {
    if (issuerUri == null || issuerUri.trim().isEmpty()) {
      throw new IllegalArgumentException("Issuer URI must not be blank");
    }
    if (issuerUri.endsWith("/")) {
      throw new IllegalArgumentException(
          "Issuer URI must not end with a trailing slash (use the discovery issuer without '/.well-known/openid-configuration')");
    }
    try {
      URI uri = new URI(issuerUri);
      String scheme = uri.getScheme();
      if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
        throw new IllegalArgumentException("Issuer URI must use http or https");
      }
      if (uri.getHost() == null || uri.getHost().isEmpty()) {
        throw new IllegalArgumentException("Issuer URI must include a host name");
      }
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Issuer URI is not a valid URI: " + issuerUri, e);
    }
  }

}
