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

import org.junit.Test;
import org.sonar.api.*;
import org.sonar.api.utils.Version;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthOidcPluginTest {

  AuthOidcPlugin underTest = new AuthOidcPlugin();



  @Test
  public void test_server_side_extensions() throws Exception {
    Plugin.Context context = setupContext(SonarQubeSide.SERVER);
    underTest.define(context);
    assertThat(context.getExtensions()).hasSize(20);
  }

  @Test
  public void test_scnner_side_extensions() throws Exception {
    Plugin.Context context = setupContext(SonarQubeSide.SCANNER);
    underTest.define(context);
    assertThat(context.getExtensions()).isEmpty();
  }


  private Plugin.Context setupContext(SonarQubeSide side){

    SonarRuntime runtime = new SonarRuntime() {
      @Override
      public Version getApiVersion() {
        return Version.create(9, 9);
      }

      @Override
      public SonarProduct getProduct() {
        return SonarProduct.SONARQUBE;
      }

      @Override
      public SonarQubeSide getSonarQubeSide() {
        return side;
      }

      @Override
      public SonarEdition getEdition() {
        return SonarEdition.COMMUNITY;
      }
    };

    return new Plugin.Context(runtime);
  }

}
