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

import java.util.regex.Pattern;

/**
 * Redacts secrets before they hit debug logs.
 */
final class SensitiveLogging {

  private static final String REDACTED = "[REDACTED]";
  private static final Pattern SENSITIVE_QUERY_PARAM = Pattern.compile(
      "(?i)(^|&)(code|access_token|refresh_token|id_token|client_secret|password)=([^&]*)");
  private static final Pattern BEARER_TOKEN = Pattern.compile("(?i)bearer\\s+[^\\s]+");
  private static final Pattern JWT_LIKE = Pattern.compile("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

  private SensitiveLogging() {
  }

  static String redactQueryString(String queryString) {
    if (queryString == null || queryString.isEmpty()) {
      return queryString;
    }
    return SENSITIVE_QUERY_PARAM.matcher(queryString).replaceAll("$1$2=" + REDACTED);
  }

  static String redactHttpBody(String body) {
    if (body == null || body.isEmpty()) {
      return body;
    }
    String redacted = BEARER_TOKEN.matcher(body).replaceAll("Bearer " + REDACTED);
    return JWT_LIKE.matcher(redacted).replaceAll(REDACTED);
  }

  static String redactAuthorizationCode(String code) {
    if (code == null || code.isEmpty()) {
      return code;
    }
    return REDACTED;
  }

}
