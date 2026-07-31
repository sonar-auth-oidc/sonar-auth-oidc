/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2017 Torsten Juergeleit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.vaulttec.sonarqube.auth.oidc;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class IssuerUriValidatorTest {

  @Test
  public void acceptsValidHttpsIssuer() {
    IssuerUriValidator.validate("https://idp.example.com/realms/sonar");
  }

  @Test
  public void rejectsTrailingSlash() {
    assertThatThrownBy(() -> IssuerUriValidator.validate("https://idp.example.com/"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("trailing slash");
  }

  @Test
  public void rejectsBlankIssuer() {
    assertThatThrownBy(() -> IssuerUriValidator.validate("  "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("blank");
  }

  @Test
  public void rejectsNonHttpScheme() {
    assertThatThrownBy(() -> IssuerUriValidator.validate("ftp://idp.example.com"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("http or https");
  }

}
