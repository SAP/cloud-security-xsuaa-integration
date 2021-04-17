package com.sap.cloud.security.samples;

import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.test.extension.SecurityTestExtension;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.GRANT_TYPE;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.assertj.core.api.Assertions.assertThat;

public class HelloJavaServletIntegrationTest {

	@RegisterExtension
	static SecurityTestExtension extension = SecurityTestExtension.forService(XSUAA)
			.useApplicationServer()
			.addApplicationServlet(HelloJavaServlet.class, HelloJavaServlet.ENDPOINT)
			.addApplicationServlet(HelloJavaServletScopeProtected.class, HelloJavaServletScopeProtected.ENDPOINT);

	@AfterEach
	public void tearDown() {
		SecurityContext.clear();
	}

	@Test
	public void requestWithoutAuthorizationHeader_unauthenticated() throws IOException {
		HttpGet request = createGetRequest(null);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
		}
	}

	@Test
	public void requestWithEmptyAuthorizationHeader_unauthenticated() throws Exception {
		HttpGet request = createGetRequest("");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
		}
	}

	@Test
	public void requestWithValidTokenWithoutScopes_unauthorized() throws IOException {
		String jwt = extension.getContext().getPreconfiguredJwtGenerator()
				.withClaimValue(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
				.createToken()
				.getTokenValue();
		HttpGet request = createGetRequest(jwt, HelloJavaServletScopeProtected.ENDPOINT);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
 			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_FORBIDDEN); // 403
		}
	}

	@Test
	public void requestWithValidToken_ok() throws IOException {
		String jwt = extension.getContext().getPreconfiguredJwtGenerator()
				.withClaimValue(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
				.withScopes(getGlobalScope("Read"))
				.withClaimValue(TokenClaims.EMAIL, "tester@mail.com")
				.createToken()
				.getTokenValue();
		HttpGet request = createGetRequest(jwt);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK); // 200
			String responseBody = EntityUtils.toString(response.getEntity());
			assertThat(responseBody)
					.contains("You ('tester@mail.com') can access the application with the following scopes: '[xsapp!t0815.Read]'.");
			assertThat(responseBody)
					.contains("Having scope '$XSAPPNAME.Read'? true");
		}
	}

	private HttpGet createGetRequest(String accessToken) {
		return createGetRequest(accessToken, HelloJavaServlet.ENDPOINT);
	}

	private HttpGet createGetRequest(String accessToken, String endpoint) {
		HttpGet httpGet = new HttpGet(extension.getContext().getApplicationServerUri() + endpoint);
		if(accessToken != null) {
			httpGet.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
		}
		return httpGet;
	}

	private String getGlobalScope(String scope) {
		return SecurityTestRule.DEFAULT_APP_ID + '.' + scope;
	}
}