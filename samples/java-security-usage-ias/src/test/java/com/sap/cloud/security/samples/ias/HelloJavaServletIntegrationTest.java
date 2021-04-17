package com.sap.cloud.security.samples.ias;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.assertj.core.util.Maps;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import uk.org.webcompere.systemstubs.rules.EnvironmentVariablesRule;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.test.SecurityTestRule.getInstance;
import static org.assertj.core.api.Assertions.assertThat;

public class HelloJavaServletIntegrationTest {

	@ClassRule
	public static SecurityTestRule rule = getInstance(Service.IAS)
			.useApplicationServer()
			.addApplicationServlet(HelloJavaServlet.class, HelloJavaServlet.ENDPOINT);

    @Rule
    public EnvironmentVariablesRule environmentVariablesRule = new EnvironmentVariablesRule("X509_THUMBPRINT_CONFIRMATION_ACTIVE", "false");

    @After
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
	public void requestWithEmptyAuthorizationHeader_unauthenticated() throws IOException {
		HttpGet request = createGetRequest("");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
		}
	}

	@Test
	public void request_withValidToken_X509Disabled() throws IOException {
        Token token = rule.getPreconfiguredJwtGenerator()
				.withClaimValue(TokenClaims.EMAIL, "john.doe@email.com")
				.createToken();
		HttpGet request = createGetRequest(token.getTokenValue());
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			assertThat(responseBody).isEqualTo("You ('john.doe@email.com') are authenticated and can access the application.");
		}
	}

    @Test
    public void request_withValidToken_X509Enabled() throws Exception {
        environmentVariablesRule.set("X509_THUMBPRINT_CONFIRMATION_ACTIVE", "true");
        String x509 = IOUtils.resourceToString("/x509Base64.txt", StandardCharsets.US_ASCII);
        String cnf = "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM";

        Token token = rule.getPreconfiguredJwtGenerator()
                .withClaimValue(TokenClaims.CNF, Maps.newHashMap(TokenClaims.X509_THUMBPRINT, cnf))
                .withClaimValue(TokenClaims.EMAIL, "john.doe@email.com")
                .createToken();

        HttpGet request = createGetRequest(token.getTokenValue());
        request.setHeader("x-forwarded-client-cert", x509);
        CloseableHttpResponse response = HttpClients.createDefault().execute(request);

        String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
        assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
        assertThat(responseBody).isEqualTo("You ('john.doe@email.com') are authenticated and can access the application.");
    }

	@Test
	public void request_withInvalidToken_unauthenticated() throws IOException {
		HttpGet request = createGetRequest(rule.getPreconfiguredJwtGenerator()
				.withClaimValue(TokenClaims.ISSUER, "INVALID Issuer")
				.createToken().getTokenValue());
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
		}
	}

	private HttpGet createGetRequest(String bearerToken) {
		HttpGet httpGet = new HttpGet(rule.getApplicationServerUri() + HelloJavaServlet.ENDPOINT);
		if(bearerToken != null) {
			httpGet.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
		}
		return httpGet;
	}
}