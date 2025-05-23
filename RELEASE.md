
## Perform release

```
cd sonar-auth-oidc
./mvnw clean install
./mvnw release:prepare
./mvnw release:perform
```


## Update SonarCloud project

```
git checkout <release tag>
./mvnw clean org.jacoco:jacoco-maven-plugin:prepare-agent package sonar:sonar -Dsonar.host.url=https://sonarcloud.io -Dsonar.organization=sonar-auth-oidc -Dsonar.login=<security token>

```


## Deploy to Marketplace

1. create a PR on the [sonar-update-center-properties repo](https://github.com/SonarSource/sonar-update-center-properties)
1. start a new topic on the [Community Forum](https://community.sonarsource.com/c/plugins) as described in [Deploying to the Marketplace](https://docs.sonarqube.org/latest/extend/deploying-to-marketplace/)
