/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2017 Torsten Juergeleit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.vaulttec.sonarqube.auth.oidc;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class SensitiveLoggingTest {

  @Test
  public void redactsAuthorizationCodeInQueryString() {
    String redacted = SensitiveLogging.redactQueryString("state=abc&code=super-secret&session=1");
    assertThat(redacted).contains("code=[REDACTED]");
    assertThat(redacted).doesNotContain("super-secret");
    assertThat(redacted).contains("state=abc");
  }

  @Test
  public void redactsTokensInHttpBody() {
    String body = "{\"access_token\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\",\"token_type\":\"Bearer\"}";
    String redacted = SensitiveLogging.redactHttpBody(body);
    assertThat(redacted).doesNotContain("eyJhbGciOiJIUzI1NiJ9");
    assertThat(redacted).contains("[REDACTED]");
  }

  @Test
  public void redactsAuthorizationCodeValue() {
    assertThat(SensitiveLogging.redactAuthorizationCode("abc123")).isEqualTo("[REDACTED]");
  }

}
