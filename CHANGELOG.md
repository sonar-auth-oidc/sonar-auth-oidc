## 3.0.2 (unreleased)

### Security
- Stop logging authorization codes, token bodies, and full userinfo JSON at DEBUG
- Validate issuer URI format (http/https, no trailing slash) before discovery
- Add HTTP connect/read timeouts on token and userinfo requests
- Auto-login skip now matches `auto-login=false` anywhere in referer (not only suffix)

### Maintenance
- Java 17 baseline (matches CI); fix `maven.compiler.target` pom typo
- Bump Nimbus OIDC SDK, AssertJ, MockWebServer, compiler and surefire plugins
- Refactor callback query parsing with UTF-8 decoding helper
