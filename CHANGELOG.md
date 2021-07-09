# Change Log
All notable changes to this project will be documented in this file.

## 2.10.2 and 0.3.2 [BETA]
- [java-security] [spring-security]
  -  Improves JWKS cache handling for OIDC token validation. This is especially relevant when using a shared IAS tenant.

## 2.10.1 and 0.3.1 [BETA]
#### Dependency upgrades
- org.springframework.boot:spring-boot 2.5.0 --> 2.5.2
- org.springframework:spring-core 5.3.7 --> 5.3.8
- org.springframework.security:spring-security-oauth2-jose 5.5.0 --> 5.5.1
- org.springframework.security:spring-security-oauth2-resource-server 5.5.0 --> 5.5.1
- org.springframework.security:spring-security-oauth2-jose 5.5.0 --> 5.5.1
- org.springframework.security:spring-boot-starter-test 5.5.0 --> 5.5.1
- org.springframework.security.oauth:spring-security-oauth2 2.5.0.RELEASE --> 2.5.1.RELEASE
- [samples] Upgraded [approuter](https://www.npmjs.com/package/@sap/approuter) version to "^10.4.3"

## 2.10.0 and 0.3.0 [BETA]
- [java-api] provides `ClientIdentity` with 2 implementations: `ClientCredentials` and `ClientCertificate`
- [token-client] 
  - `XsuaaTokenFlows` supports X.509 authentication method. In order to enable X.509 you probably need to provide ``org.apache.httpcomponents:httpclient`` as dependency and need to configure ``XsuaaTokenFlows`` differently:
    - `XsuaaDefaultEndpoints(url)` must be replaced with `XsuaaDefaultEndpoints(<OAuth2ServiceConfiguration>)`.
    - `DefaultOAuth2TokenService` constructors that are not parameterized with `CloseableHttpClient` are deprecated, as they do not support X.509.
    - `XsuaaOAuth2TokenService` constructors that are not parameterized with `RestOperations` are deprecated, as they do not support X.509.
    - Find more detailed information [here](/token-client).
  - ``SSLContextFactory`` class, which was marked as deprecated, is moved to `com.sap.cloud.security.mtls` package.
  - logs 'WARN' message, in case application has not overwritten the default http client. Find further information about that [here](/token-client#common-pitfalls).
- [java-security] 
  - `IasXsuaaExchangeBroker` supports X.509 based token exchange. In case the token exchange is done via `XsuaaTokenAuthenticator` you need to provide a http client that is prepared with ssl context.
  - `JwtIssuerValidator.java` supports custom domains of identity service. If `ias_iss` is given and not empty, `JwtIssuerValidator.java` checks whether its a valid url and checks whether this matches one of the valid domains of the identity service. The check whether `ias` matches to any given domains is skipped in that case.
  - The token keys cache does not accept cache time longer than 15 minutes.
- [spring-xsuaa] and starter
  - As of Spring Security version 5.5.0 only `BadJwtException` results in `InvalidBearerTokenException`, which are handled and mapped to ``401`` status code. Consequently, `XsuaaJwtDecoder` raises `BadJwtException`s instead of `JwtException`s.
  - `XsuaaTokenFlowAutoconfiguration` supports X.509 based authentication. You need to provide ``org.apache.httpcomponents:httpclient`` as dependency.
  - `IasXsuaaExchangeBroker` can be configured with (autoconfigured) `XsuaaTokenFlow` to enable X.509 based authentication.
  - As of version ``2.10`` a warning `In productive environment provide a well configured client secret based RestOperations bean.` is exposed to the application log in case the default implementation of ``RestOperations`` is used and not overwritten by an own well-defined one. See also [here](/spring-xsuaa#resttemplate--restoperations).
- [spring-security] and starter
  - `XsuaaTokenFlowAutoconfiguration` supports X.509 based authentication. You need to provide ``org.apache.httpcomponents:httpclient`` as dependency.
  - `HybridJwtDecoder` raises `BadJwtException`s instead of `AccessDeniedException`s.
  - As of version ``2.10`` a warning `In productive environment provide a well configured client secret based RestOperations bean.` is exposed to the application log in case the default implementation of ``RestOperations`` is used and not overwritten by an own well-defined one. 
- [samples/java-tokenclient-usage] uses X.509 based authentication for `XsuaaTokenflows`
- [samples/spring-security-xsuaa-usage] deprecates the xsuaa security descriptor with a client secret authentication, default now is X.509 based authentication.
- [samples/spring-security-hybrid-usage] switched now to X.509 based authentication.

## 2.9.0 and 0.2.0 [BETA]
- [java-security] and [spring-security] validates IAS OIDC tokens from multiple IAS tenants and zones. <br>**Prerequisite:** identity service broker needs to provide list of `domains` via `VCAP_SERVICES`-`identity`-`credentials`.
- [spring-security] Resource Server raises ``InvalidBearerTokenException`` in case token couldn't be successfully validated (as documented [here](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver-bearertoken-failure)). Adapt your configuation locally according to this [documentation](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/spring-security#minimal-configuration-required).

#### Dependency upgrades
- commons-io:commons-io 2.8.0 --> 2.9.0
- org.springframework.boot:spring-boot 2.4.5 --> 2.5.0
- org.springframework:spring-core 5.3.6 --> 5.3.7
- org.springframework.security:spring-security-oauth2-jose 5.4.6 --> 5.5.0
- org.springframework.security:spring-security-oauth2-resource-server 5.4.6 --> 5.5.0
- org.springframework.security:spring-security-oauth2-jose 5.4.6 --> 5.5.0
- org.springframework.security:spring-boot-starter-test 5.4.6 --> 5.5.0
- org.junit.jupiter 5.7.1 --> 5.7.2
- org.mockito:mockito-core 3.9.0 --> 3.10.0

## 2.8.13
- [token-client] **Bug fix** As of now, client-credential and jwt bearer user tokens are not cached in case tokenflow is configured with zone-id (instead of subdomain).
- [java-security] provides `SapIdToken.getCnfX509Thumbprint()` method to provide thumbprint of certificate, in case token was requested via X509 based authentication.
- [java-api] provides `Token.getGrantType()` method, proprietary `GrantType.CLIENT_X509` gets deprecated.
  
## 0.1.6 [BETA]
- [spring-security] and [spring-security-starter] `HybridIdentityServicesAutoConfiguration` supports Identity service configuration alone, by setting up `IasJwtDecoder`

## 2.8.12 and 0.1.5 [BETA]
- [token-client] ```OAuth2ServiceException``` provides ```getHttpStatusCode()```. This allows applications to retry e.g. in case of ```429``` - when the request was rate limited.

#### Dependency upgrades
- spring.security.version 5.4.5 --> 5.4.6
- spring.core.version 5.3.5 --> 5.3.6
- spring.boot.version 2.4.4 --> 2.4.5
- org.json.version 20201115 --> 20210307
- junit.version 4.13.1 --> 4.13.2
- junit-jupiter.version 5.7.0 --> 5.7.1
- reactor.version 3.4.2 --> 3.4.5
- reactor.test.version 3.4.2 --> 3.4.5

    
## 2.8.10 and 0.1.4 [BETA]
- [spring-xsuaa] introduced spring properties for IAS -> Xsuaa token exchange activation, as described [here](/spring-xsuaa/README.md#ias-to-xsuaa-token-exchange)
- [java-security-test] uses jetty BoM to fix CVE-2021-28164 and CVE-2021-28165.
  - jetty 9.4.38.v20210224 --> 9.4.39.v20210325

## 2.8.9 and 0.1.3 [BETA]
- [java-security-test] and java samples to fix CVE-2021-28164 and CVE-2021-28165.
  - jetty 9.4.38.v20210224 --> 9.4.39.v20210325
- [spring-xsuaa]
  - exclude transient dependency to net.minidev:json-smart to resolve CVE-2021-27568
- [xsuaa-spring-boot-starter] [resourceserver-security-spring-boot-starter]
  - spring-boot-starter 2.4.3 --> 2.4.4
  - spring-boot-starter-security 2.4.3 --> 2.4.4
  - net.minidev:json-smart 2.3 --> 2.4.2 to resolve CVE-2021-27568
  
## 2.8.8 and 0.1.2 [BETA]
- [java-security-test] and java samples
  - jetty 9.4.36.v20210114 --> 9.4.38.v20210224 (seems to be incompatible with javax.servlet-api 3.1.0)
  - javax.servlet:javax.servlet-api 3.1.0 --> 4.0.1 (recommended version)
- [java-security] supports with ``SpringSecurityContext`` a way to read tokens from Spring's `SecurityContextHolder`, in case a token was set by the application using one of these client-libraries:
  -  `org.springframework.security.oauth:spring-security-oauth2`
  -  `com.sap.cloud.security.xsuaa:spring-xsuaa`
  -  `com.sap.cloud.security:spring-security`


## 2.8.7 and 0.1.1 [BETA]
- [xsuaa-spring-boot-starter] and [resourceserver-security-spring-boot-starter (BETA)]
  - spring.core.version 5.3.3 --> 5.3.4
  - spring.boot.version 2.4.2 --> 2.4.3
  - spring.security.version 5.4.2 --> 5.4.5
- use ``spring-boot-starter-parent`` version 2.4.3 in spring samples.
  
##  2.8.6
- [token-client] Next to subdomain `XsuaaTokenFlows.clientCredentialsTokenFlow()` supports Zone id.

## 0.1.0 [BETA] :star:
- [spring-security] new spring boot security client library that supports Token validation from XSUAA and IAS identity provider in parallel as described [here](/spring-security). An initial migration guide on how to migrate from ``spring-xsuaa`` is available [here](/spring-security/Migration_SpringXsuaaProjects.md).

## 2.8.5
- [java-security] load environment from `VCAP_SERVICES` formatted json file (#471)
- [java-security] performance: make sure ServiceLoader loads services only once (#467)
- [java-api] move `getAttributeFromClaimAsString` and `getAttributeFromClaimAsStringList` methods from `AccessToken` to its `Token` parent interface.

## 2.8.4
- [java-security] Make HybridTokenFactory more failure tolerant 
- [spring-xsuaa-test] Prefills "ext_atr" "enhancer" with XSUAA

#### Dependency upgrades
- [all]
  - commons-io 2.6 --> 2.8.0
  - org.apache.httpcomponents » httpclient 4.5.9 --> 4.5.13
  - spring.core.version 5.3.2 --> 5.3.3
  - spring.boot.version 2.4.1 --> 2.4.2
- [java-security-test]
  - org.eclipse.jetty 9.4.35.v20201120 --> 9.4.36.v20210114
- [token-client]
  - caffeine 2.8.6 --> 2.8.8
  - org.json 20200518 --> 20201115
- [spring-xsuaa]
  - caffeine 2.8.6 --> 2.8.8
  - reactor-core 	3.3.7.RELEASE --> 3.4.2
  - log4j-to-slf4j 2.13.3 --> 2.14.0
  
  
## 2.8.3
- [java-api] ``AccessToken`` exposes the ```getSubaccountId()``` method. Further information about the usage of ```getSubaccountId()``` and ```getZoneId()``` can be read [here](https://github.com/SAP-samples/teched2020-DEV263#changed-api-for-multi-tenant-applications-to-determine-tenant-identifier-getsubaccountid-replaced-by-getzoneid).
- [java-api] [java-security] allows hybrid token creation via `Token.create(String encodedToken)`. The feature is available when using token authenticator. In order to avoid `ServiceLoader` issues, make sure that you don't mix up different versions of these client libraries. E.g., its not possible to use `com.sap.cloud.security:java-api:2.8.3` together with `com.sap.cloud.security:java-security:2.8.2`. See also [here](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/java-security#common-pitfalls).
- [samples/sap-java-buildpack-api-usage] uses [SAP Java Buildpack BoM](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/6c6936e8e4ea40c9a9a69f6783b1e978.html) ([sample](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/samples/sap-java-buildpack-api-usage/pom.xml)).
- [token-client] `UserTokenFlow` enhances request with `X-zid` header that corresponds to zone id.

## 2.8.2
- [java-security]  
  - HOTFIX for ``2.8.1`` version.
  - *Beta release* of ias2xsuaa token exchange. Further information can be found [here](/java-security#ias-to-xsuaa-token-exchange).
  
## 2.8.1
- [spring-xsuaa]   
  - *Beta release* of ias2xsuaa token exchange. Further information can be found [here](/spring-xsuaa#ias-to-xsuaa-token-exchange).
  - Replaces dependencies to JSON Parser of ``net.minidev`` with `org.json` (fixes #414).
  
#### Dependency upgrades
- spring.boot.version 2.3.5.RELEASE --> 2.4.1
- spring.core.version 5.2.10.RELEASE --> 5.3.2
- spring.security.version 5.3.5.RELEASE --> 5.4.2

## 2.8.0
- [java-security] 
  - `getClientId()` method was added to `Token` interface. `getClientId()` method should be used instead of `getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)`. `TokenClaims.XSUAA.CLIENT_ID` is deprecated.
  - Supports IAS token validation. `IAS_SERVICE_NAME` has not be provided any longer. You can find a sample [here](/samples/java-security-usage-ias).
- [java-security-test] In case you like to overwrite the client id using `JwtGenerator` using `withClaimValue()` or `withClaimValues()` method, it's recommended to set the `azp` claim instead using `withClaimValue(TokenClaims.AUTHORIZATION_PARTY, "T000310")`.
- [spring-xsuaa] 
  - `getClientId()` method implementation of `Token` interface has been changed. Using `azp` and as fallback `aud` and `cid` claims to obtain client id.
- :warning: **backward incompatible change:** usage of deprecated org.springframework.security.oauth:spring-security-oauth2 dependency in `OAuth2AuthenticationConverter` was removed. 
  `OAuth2AuthenticationConverter.convert()` method return type has changed from `org.springframework.security.oauth2.provider.OAuth2Authentication` to `org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication`
  - Migration tips
    - when necessary, org.springframework.security.oauth:spring-security-oauth2 dependency need to be provided explicitly 
    - `OAuth2WebSecurityExpressionHandler()` won't work in conjunction with `OAuth2AuthenticationConverter`, as it expects `OAuth2Authentication` class instead of `BearerTokenAuthentication` when deriving authorization claims. Use `hasAuthority()` or `hasAnyAuthority()` instead of explicitly defined `expressionHandler(new OAuth2WebSecurityExpressionHandler())` and `access()` expression for authorized requests. 
- The following dependency was removed:
    - org.springframework.security.oauth:spring-security-oauth2
- The following dependencies were updated:
    - spring.boot.version 2.3.4.RELEASE --> 2.3.5.RELEASE
    - spring.core.version 5.2.9.RELEASE --> 5.2.10.RELEASE
    - spring.security.version 5.3.4.RELEASE --> 5.3.5.RELEASE
    - caffeine.version 2.8.2 --> 2.8.6
    
## 2.7.8
- [java-security-test] Supports JUnit 5 Tests with `XsuaaExtension`, `IasExtension` and `SecurityTestExtension` as documented [here](/java-security-test#junit-5).
- [spring-xsuaa-starter] Upgrade Spring versions:
  - spring.boot.version: 2.3.1.RELEASE --> 2.3.4.RELEASE
  - spring.core.version: 5.2.8.RELEASE --> 5.2.9.RELEASE
- The following dependencies were updated:
  - Jetty 9.4.24.v20191120 --> 9.4.31.v20200723
  - javax.servlet-api.version 3.0.1 --> 3.1.0
  - Apache HTTP client 4.5.8 --> 4.5.9
  - Wiremock 2.25.1 --> 2.27.2
- [java-security] Does not fail in case of Xsuaa services of type: `apiacess` (#382).

## 2.7.7
- [spring-xsuaa] Update Spring versions
  - spring.core.version: 5.2.7.RELEASE --> 5.2.8.RELEASE
  - spring.security.version: 5.3.3.RELEASE --> 5.3.4.RELEASE
- [java-security-test] `SecurityTest` and `SecurityTestRule` provides a better support for integration tests with a mockserver. It is now possible to upload the configuration and the token from a json file. Take our integration tests as a sample [java-security-it](/java-security-it).
- [java-security] `DefaultJsonObject.getAsStringList(propertyName)` parses the JSON object for a given property and returns a `String` list. This works also in case the property is not a JSON array but a JSON String.
- [java-security-it] New integration test project. Existing integration tests have been restructured and moved here. Additionally, JWT token validation performance tests have been added for java-security and spring-xsuaa.

## 2.7.6
- Fixes `ClientCredentialsTokenFlow.scopes()` and `UserTokenFlow.scopes()` to support multiple scopes. The scope form parameter has to provide a space-delimited list (and not comma-delimited list).
- [java-security] Improve compatibility of `SAPOfflineTokenServicesCloud`
  - There was incompatibility in the implementation of `SAPOfflineTokenServicesCloud` that caused the `remoteUser` of the `HttpServletRequest` to always return the client id of the XSUAA service binding. This was changed so that it now works like in the old implementation. This means that the `remoteUser` now returns either the `user_name` claim of the token for user tokens or the value of the client id `cid` claim of the token for all other tokens (e.g. client tokens).

## 2.7.5
- [java-api] `AcessToken` provides  
  - `getAttributeFromClaimAsString(String claimName, String attributeName)` to access for example `ext_attr` values such as `subaccountid`
  - `getAttributeFromClaimAsStringList(String claimName, String attributeName)` to access for example `xs.user.attributes` values such as `custom_role`
- [java-security] provide debug logs for failing token validation, see [troubleshoot](/java-security/README.md#troubleshoot).
- [java-security-test] Fixed default value for jku token header to `http://localhost/token_keys`
- [samples] Upgraded [approuter](https://www.npmjs.com/package/@sap/approuter) version to "^8.2.0"
- [spring-xsuaa-starter] Upgrade Spring versions:
  - spring.boot.version: 2.3.0.RELEASE --> 2.3.1.RELEASE
  - spring.core.version: 5.2.6.RELEASE --> 5.2.7.RELEASE
  - spring.security.version: 5.3.2.RELEASE --> 5.3.3.RELEASE
  - spring-security-oauth2.version: 2.4.1.RELEASE --> 2.5.0.RELEASE 

## 2.7.4
- [java-security] Audience Validation validates to true when the derived `client_id` of broker-clone token matches the trusted client. This is relevant to support tokens of grant type `user_token` that contains no scopes.

## 2.7.3
- [java-security] 
  - Audience Validation is skipped when `client_id` of token exactly matches the trusted client. This is relevant to support tokens of grant type `user_token` that contains no scopes.
  - provides the subaccount identifier from the `ext_attr` claim.
- [spring-xsuaa] provides the subaccount identifier from the `ext_attr` claim.

## 2.7.2
- [java-security] 
  - Audience Validation accepts tokens of grant type `user_token` that does not provide `aud` claim. In that case `JwtAudienceValidator` derives the audiences from the scopes.
#### :exclamation: IMPORTANT Update
  - Use `getSubaccountId()` only to fetch the subaccount id, e.g. for calling the metering API for user-based pricing. 
  - **In case you are interested in the customers tenant GUID make use of `getZoneId()` instead!** 
  - In upcoming releases - especially for new subaccounts - subaccount id will no longer match the tenant GUID which is provided via the xsuaa access token as `zid` claim or via the ias oidc token as `zone_uuid` claim.

## 2.7.1

- [java-security] 
  - `XSUserInfoAdapter` provides now the subdomain that is required for token exchange via `getSubdomain()` method.
  - Avoid warning messages "IAS Service is not yet supported!". #273
  - rename Token claim "sap_uid" to „user_uuid“.
  - Token Key Cache can now be customized via `XsuaaTokenAuthenticator`.
  - `XSUserInfoAdapter` supports `requestTokenForUser()` method.
  - set validators to package private, you can customize the JWT validators using the `JwtValidatorBuilder`.
  - Create validation results lazy. Avoid false warning validation results from `JwtAudienceValidator` (#290), e.g.   
`Jwt token with audience [<appId>, uaa] is not issued for these clientIds: [<appId>].`
- [spring-xsuaa] Improve logs of Audience Validators.
- [spring-xsuaa-starter] Upgrade Spring versions:
  - spring.boot.version: 2.2.6.RELEASE --> 2.3.0.RELEASE
  - spring.core.version: 5.2.5.RELEASE --> 5.2.6.RELEASE
  - spring.security.version: 5.3.1.RELEASE --> 5.3.2.RELEASE
  - spring.security.oauth2:  2.4.0.RELEASE -> 2.4.1.RELEASE
- [spring-xsuaa-test]  
  - renamed file `privateKey.txt` to `spring-xsuaa-privateKey.txt` and `publicKey.txt` to `spring-xsuaa-publicKey.txt` to avoid name clashes in context of CAP, which results in a strange `IllegalArgumentException:failed to construct sequence from byte[]: DEF length 1213 object truncated by 2`. This can happen when you use `java-security-test` and `spring-xsuaa-test` in parallel.
  - **For new applications `spring-xsuaa-test` can be replaced in favor of `java-security-test` for unit testing. For testing your app locally you can setup your local environment with the `VCAP_SERVICES` in order to test with your XSUAA instance on Cloud Foundry.**
- [token-client]
  - more detailed debug logs and details to exception; decoded token gets logged.
  - supports optional `scope` parameter to reduce scopes that are provided via `CientCredentialsTokenFlow` or `UserTokenFlow`.
  - By default requested tokens are now cached. You can disable the cache globally or per request as described [here](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/token-client).
  - never log an encoded token! Instead you can log the `OAuth2TokenResponse` itself: the `toString()` method provides the content of the decoded token (clear text). Be aware that this contains sensitive user data.





## 2.7.0
- [token-client] By default requested tokens are now cached. You can disable the cache globally or per request as described [here](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/token-client).
- [java-security]  
  - `XSUserInfoAdapter` provides now the subdomain that is required for token exchange via `getSubdomain()` method.
  - Avoid warning messages "IAS Service is not yet supported!".
- [spring-xsuaa-test]  
  - renamed file `privateKey.txt` to `spring-xsuaa-privateKey.txt` and `publicKey.txt` to `spring-xsuaa-publicKey.txt` to avoid name clashes in context of CAP, which results in a strange `IllegalArgumentException:failed to construct sequence from byte[]: DEF length 1213 object truncated by 2`. This can happen when you use `java-security-test` and `spring-xsuaa-test` in parallel.
  - For new applications `spring-xsuaa-test` can be replaced in favor of `java-security-test` for unit testing. For testing your app locally you can setup your local environment with the `VCAP_SERVICES` in order to test with your XSUAA instance on Cloud Foundry.  
- [spring-xsuaa-starter] Upgrade Spring versions:
  - spring.boot.version: 2.2.6.RELEASE --> 2.3.0.RELEASE
  - spring.core.version: 5.2.5.RELEASE --> 5.2.6.RELEASE
  - spring.security.version: 5.3.1.RELEASE --> 5.3.2.RELEASE
  - spring.security.oauth2:  2.4.0.RELEASE -> 2.4.1.RELEASE

## 2.6.2
- [java-security] `XSUserInfoAdapter` provides full compatible implementation of `com.sap.xsa.security.container.XSUserInfo.java` interface. Support token exchanges using `XsuaaTokenFlows` api.
- [spring-xsuaa] Improve support of multiple XSUAA Bindings as described [here](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/spring-xsuaa/Migration_JavaContainerSecurityProjects.md#multiple-xsuaa-bindings).

## 2.6.1
- [spring-xsuaa-starter] Upgrade Spring versions:
  - spring.boot.version: 2.2.5.RELEASE --> 2.2.6.RELEASE
  - spring.core.version: 5.2.4.RELEASE --> 5.2.5.RELEASE
  - spring.security.version: 5.2.2.RELEASE --> 5.3.1.RELEASE

## 2.6.0
- [spring-xsuaa] SpringSecurityContext throws `AccessDeniedException` instead of `IllegalStateException` when authentication does not contain principal of type Token.
- [java-security] `JwtAudienceValidator` Support Audience Validation of Xsuaa Broker clones (multiple xsuaa bindings): NGPBUG-111540.
- [java-security-test] Basic support fo JUnit 5 (Jupiter).
- [java-security-test] Deprecation: `SecurityTestRule#getWireMockRule()` needs to be replaced by `getWireMockServer()`.
- [java-security-test] One instance of `SecurityTestRule` should run only one WireMock server. With that `@ClassRule SecurityTestRule` can be declared in a base class.

## 2.5.3
- [spring-xsuaa] `XsuaaJwtDecoder` supports verificationkey from `VCAP_SERVICES` as fallback public key.
- [spring-xsuaa] when using `auto-configuration` and expose your own `RestTemplate` `RestOperations` bean, have a look at this [documentation](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/spring-xsuaa#resttemplate--restoperations).
- [java-security-test] `JwtGenerator` supports `withLocalScopes()`.
- [java-security] `SapIdToken` should return value of claim "sap_uid" (SAPGlobalUserID) as Principal name.
- [java-security] `JwtAudienceValidator` Support Audience Validation of Xsuaa Broker clones: NGPBUG-111540.
- [java-api] enhanced with config interfaces, which are relevant for SAP Java Buildpack.
- [api] changes `XSUserInfoException` from `Exception` to `RuntimeException`. This reflects the json-lib change in `java-container-security` (version `3.12.0`).

## 2.5.2
- [java-api], [java-security], [token-client] works with logger api `slf4j-api` and does no longer provide the slf4j-implementation. Please have a look at the [java-security/README.md#logging](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/java-security/README.md#logging) documentation.
- [xsuaa-spring-boot-starter] update spring-boot (security) dependency versions [#239](https://github.com/SAP/cloud-security-xsuaa-integration/issues/239).
- [java-security-test] `SecurityTestRule.setKeys` allows to customize private/public keys that are located in the resource path, e.g. `src/main/resources` or `src/test/resources`.
- [java-security-test] configures the modulus of the public key provided by `WireMock`. With that the public key can be consumed by the Nimbus Jwt decoder.
- [samples/spring-security-xsuaa-usage] demonstrates how to setup JUnit tests using `java-security-test` library.

## 2.5.1
- [java-api] As preparation for the SAP Java Buildpack the interfaces, as well as the `SecurityContext` is extracted to [java-api](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/java-api).
- [java-security] `AccessToken`s provided via the `SpringSecurityContext` should also support the `hasLocalScope` method.

## 2.5.0
- [java-security-test] `JwtGenerator.withClaimsFromFile` accepts claims from a file.
- [java-security] Provides with `SpringSecurityContext` an alternative way of accessing jwt tokens for Spring applications in asynchronous threads.
- [token-client] The `UserTokenFlow` has used the "user_token" grant type together with the "refresh_token" grant type in order to do the token exchange.
After the consumption of UAA 4.27 we can adapt the grant type "urn:ietf:params:oauth:grant-type:jwt-bearer". 
This reduces the round trips to the XSUAA from 2 to 1. Further, it eliminates the need for the user to have scope "uaa.user". The feature flag `xsuaa.userTokenFlow.useJwtBearer` has become obsolete. 

## 2.4.5
- [java-security] Initial / released version of the new plain Java security libraries as documented [here](/README.md#token-validation-for-java-applications).

## 2.3.2
- [spring-xsuaa] Fix vulnerability issues and increased Spring versions.
- [spring-xsuaa] **Bug fix** in TokenBrokerResolver: Second configured authentication method was ignored.

## 2.3.0
- Issue: Spring tests fail with version `2.2.0`, when auto-configuration is disabled and no `RestOperations` bean is specified.
- [token-client] Supports basically JWT Bearer Token Grant as documented [here](https://docs.cloudfoundry.org/api/uaa/version/74.4.0/index.html#jwt-bearer-token-grant).
- [token-client] **Bug fix** for state issue in HttpHeaderFactor ([#200](/issues/200)) that causes interference between different types of token flows.
- [spring-xsuaa] xsuaa bindings of plan `apiaccess` does not cause an error, as they get ignored for token validation.

## 2.2.0
- [spring-xsuaa] `PropertySourceFactory` supports custom property sources and default can optionally be disabled with  `spring.xsuaa.disable-default-property-source=true`
- [spring-xsuaa] Supports Spring Core `5.2.0.RELEASE`and Spring Boot `2.2.0.RELEASE`
- [spring-xsuaa] Deprecates `TokenUrlUtils` in favor of `OAuth2ServiceEndpointsProvider`
- Internally, we've cleaned up maven dependencies (converged versions) and 
  - removed transient dependency of `spring-security-oauth2` to `jackson`.
  - introduced `org.owasp.dependency-check-maven` which performs CVSS checks.
- [token-client] Supports password token flows as documented [here](/token-client).

## 2.1.0
* `token-client` library supports [Apache Http Client](https://hc.apache.org/) (without any Spring dependencies). Have also a look at the [java-tokenclient-usage](/samples/java-tokenclient-usage) sample application.
* Fix CVE-2018-1000613 by removing unnecessary dependencies ([issue 144](https://github.com/SAP/cloud-security-xsuaa-integration/issues/144)).
* Makes `XsuaaMockWebServer` more robust.

## 2.0.0
* Deleted package `com.sap.xs2.security.container` in order to avoid Class Loader issues, when an application makes use of SAP-libraries using the SAP-internal container lib like CAP. 
  - As already mentioned use `SpringSecurityContext` class instead of `SecurityContext` class.
* Removed deprecated methods:
  - `XsuaaServiceConfiguration.getTokenUrl()`
  - `XsuaaToken.getClaimAccessor()` is not required anymore as `Xsuaa` itself implements `JwtClaimAccessor `.
* Deprecated `TokenBroker` interface and its implementation `UaaTokenBroker`, as this is going to be replaced with the `OAuth2TokenService` interface which is provided by the new `token-client` library. If you wish to configure / pass your `RestTemplate` you can pass an instance of `OAuth2TokenService`:  

```java
new TokenBrokerResolver( 
  <<your configuration>>, 
  <<your cache>>, 
  new XsuaaOAuth2TokenService(<<your restTemplate>>), 
  <<your authenticationInformationExtractor>>);
```
* `TokenUlrUtils` class is now package protected and will be deleted with version.
* `token-client` library supports basically Password-Grant Access Tokens.


## 1.7.0
* We now provide a new slim [`token-client`](/token-client/README.md) library with a `XsuaaTokenFlows` class, which serves as a factory for the different flows (user, refresh and client-credentials). This deprecates the existing `Token.requestToken(XSTokenRequest)` API. 
  * The `token-client` library can be used by plain Java applications. 
  * Auto-configuration is provided for Spring Boot applications only, when using XSUAA Spring Boot Starter. 

* **ANNOUNCEMENT: Please be aware that with version `2.0.0` we want to get rid of package `com.sap.xs2.security.container` in order to avoid Class Loader issues, when an application makes use of SAP-libraries using the SAP-internal container lib.**


## 1.6.0
* Provides spring starter for spring-xsuaa, which enables auto-configuration
* Supports reactive ServerHttpSecurity (Spring webflux). Have a look at the (webflux sample application)[samples/spring-webflux-security-xsuaa-usage/README.md]
* Some enhancements for XSUAA integration
* To make sure that the Spring SecurityContext is always initialized with a validated token use `SpringSecurityContext.init()` method as documented [here](spring-xsuaa/README.md)
* Use `SpringSecurityContext` instead of `SecurityContext`, which gets deprecated in this version. 

### Incompatible changes
* As of version `1.6.0` you need to make use of XSUAA Spring Boot Starter in order to leverage auto-configuration (see "Troubleshoot" section [here](spring-xsuaa/README.md#troubleshoot))


## 1.5.0
* Supports `jku` URI which is provided as part of the JSON Web Signature (JWS). The `jku` of the Jwt token header references the public key URI of the Xsuaa OAuth Authorization Server, and needs to match to the `xsuaa.uaadomain`.
* Completely customizable auto-configurations so that apps can override the spring-xsuaa defaults:
  * auto-configuration for Xsuaa OAuth Authorization Server is documented [here](spring-xsuaa#auto-configuration).
  * auto-configuration for Xsuaa Mock Server configuration can be found [here](spring-xsuaa-mock/src/main/java/com/sap/cloud/security/xsuaa/mock/autoconfiguration/XsuaaMockAutoConfiguration.java).
* Uses apache slf4j Logger for better log analysis on Cloud Foundry. This is provided with org.springframework.boot:spring-boot-starter-logging.
* Improves and enhances [sample application](samples/spring-security-xsuaa-usage).
* Renames class `TokenImpl` to `XsuaaToken`. Furthermore for convenience `XsuaaToken` subclasses `org.springframework.security.oauth2.jwt.Jwt`.
* Subclassing of `TokenAuthenticationConverter` is no longer allowed, instead `TokenAuthenticationConverter` can be configured with your own `AuthoritiesExtractor` implementation (an example can be found [here](spring-xsuaa/src/test/java/com/sap/cloud/security/xsuaa/token/TokenAuthenticationConverterTest.java#L103)).
* Please note that the port of the mock web server that is provided with the [xsuaa mock library](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/spring-xsuaa-mock) had to be defined statically. It runs now always on port 33195.
* Find more complex examples here: https://github.com/SAP/cloud-application-security-sample

## 1.4.0
* API method to query [token validity](spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/token/Token.java#L167)
* Bugfix in basic authentication support: allow  usage of JWT token or basic authentication with one configuration
* Allows overwrite / enhancement of XSUAA jwt token validators
* Allow applications to initialize of Spring SecurityContext for non HTTP requests. As documented [here](spring-xsuaa/README.md)

## 1.3.1
* Broker plan validation failed due to incorrect audience validation
## 1.3.0
* JwtGenerator offers enhancement options: custom claims and audience
* Test framework support for multi tenancy

## 1.2.0
* Eases enhancement of TokenAuthenticationConverter ([issue 23](https://github.com/SAP/cloud-security-xsuaa-integration/issues/23))
* Makes XsuaaAudienceValidator more robust ([issue 21](https://github.com/SAP/cloud-security-xsuaa-integration/issues/21))
* XSTokenRequest accepts custom RestTemplate ([issue 25](https://github.com/SAP/cloud-security-xsuaa-integration/issues/25))
* Provides spring-xsuaa-test library with JWTGenerator ([issue 29](https://github.com/SAP/cloud-security-xsuaa-integration/issues/29))
* Provides spring-xsuaa-mock library with XSUAA authentication mock web server for offline token key validation ([issue 30](https://github.com/SAP/cloud-security-xsuaa-integration/issues/30))


## 1.1.0

* Spring-Security 5 integration libraries. Added AudienceValidator
* Spring-Security 5 Support for basic authentication

## 1.1.0.RC1

* Initial version including spring-security 5 integration libraries


## 1.0.0

* Initial version of the api for SAP Java Buildpack

