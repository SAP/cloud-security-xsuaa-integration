package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.util.HttpClientTestFactory;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class IasTokenAuthenticatorTest {

	private final static HttpServletResponse HTTP_RESPONSE = Mockito.mock(HttpServletResponse.class);

	private final SapIdToken token;
	private final SapIdToken tokenWithCnf;
	private final SapIdToken tokenInvalidCnf;
	private final String x509;

	private AbstractTokenAuthenticator cut;

	public IasTokenAuthenticatorTest() throws IOException {
		token = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
		tokenWithCnf = new SapIdToken(IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", UTF_8));
		tokenInvalidCnf = new SapIdToken(IOUtils.resourceToString("/iasTokenInvalidCnfRSA256.txt", UTF_8));
		x509 = IOUtils.resourceToString("/cf-forwarded-client-cert.txt", UTF_8);
	}

	@Before
	public void setUp() throws IOException {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withProperty(CFConstants.URL, "https://myauth.com")
				.withClientId("T000310")
				.build();

		CloseableHttpClient httpClientMock = Mockito.mock(CloseableHttpClient.class);

		CloseableHttpResponse oidcResponse = HttpClientTestFactory
				.createHttpResponse("{\"jwks_uri\" : \"https://application.auth.com/oauth2/certs\"}");
		CloseableHttpResponse tokenKeysResponse = HttpClientTestFactory
				.createHttpResponse(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));
		when(httpClientMock.execute(any(HttpGet.class)))
				.thenReturn(oidcResponse)
				.thenReturn(tokenKeysResponse);

		cut = new IasTokenAuthenticator()
				.withServiceConfiguration(configuration)
				.withHttpClient(httpClientMock);
	}

	@Test
	public void validateWhenConfigurationIsNull() {
		cut = new IasTokenAuthenticator();

		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);
		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason())
				.contains("Unexpected error occurred: There must be a service configuration.");
	}

	@Test
	public void validateRequest_noHeader_isUnauthenticated() {
		HttpServletRequest httpRequest = createRequestWithoutToken();

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason()).contains("Authorization header is missing");
	}

	@Test
	public void validateRequest_invalidToken_isUnauthenticated() {
		String errorMessage = "JWT token does not consist of 'header'.'payload'.'signature'";
		HttpServletRequest httpRequest = createRequestWithToken("Bearer invalid");

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.isAuthenticated()).isFalse();
		assertThat(response.getUnauthenticatedReason()).contains(errorMessage);
	}

	@Test
	public void validateRequest_validToken_containedInSecurityContext() {
		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason()).isEmpty();
		assertThat(response.isAuthenticated()).isTrue();
		assertThat(response.getToken()).isSameAs(SecurityContext.getToken());
	}

	@Test
	public void validateRequest_validTokenWithCnf_noCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenWithCnf.getTokenValue());

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason())
				.contains("Error during token validation: Certificate validation failed");
		assertThat(response.isAuthenticated()).isFalse();
	}

	@Test
	public void validateRequest_validTokenInvalidCnf_withCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenInvalidCnf.getTokenValue());
		when(httpRequest.getHeader("x-forwarded-client-cert")).thenReturn(x509);

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason())
				.contains("Error during token validation: Certificate validation failed");
		assertThat(response.isAuthenticated()).isFalse();
	}

	@Test
	public void validateRequest_validTokenWithCnf_withCertificate() {
		HttpServletRequest httpRequest = createRequestWithToken(tokenWithCnf.getTokenValue());
		when(httpRequest.getHeader("x-forwarded-client-cert")).thenReturn(x509);

		TokenAuthenticationResult response = cut.validateRequest(httpRequest, HTTP_RESPONSE);

		assertThat(response.getUnauthenticatedReason()).isEmpty();
		assertThat(response.isAuthenticated()).isTrue();
	}

	@Test
	public void validateRequest_validToken_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue());
		ValidationListener validationListener1 = Mockito.mock(ValidationListener.class);
		ValidationListener validationListener2 = Mockito.mock(ValidationListener.class);

		cut.withValidationListener(validationListener1)
				.withValidationListener(validationListener2)
				.validateRequest(httpRequest, HTTP_RESPONSE);

		Mockito.verify(validationListener1, times(1)).onValidationSuccess();
		Mockito.verify(validationListener2, times(1)).onValidationSuccess();
		Mockito.verifyNoMoreInteractions(validationListener1);
		Mockito.verifyNoMoreInteractions(validationListener2);
	}

	@Test
	public void validateRequest_invalidToken_listenerIsCalled() {
		HttpServletRequest httpRequest = createRequestWithToken(token.getTokenValue() + "B");
		ValidationListener validationListener1 = Mockito.mock(ValidationListener.class);
		ValidationListener validationListener2 = Mockito.mock(ValidationListener.class);

		cut.withValidationListener(validationListener1)
				.withValidationListener(validationListener2)
				.validateRequest(httpRequest, HTTP_RESPONSE);

		Mockito.verify(validationListener1, times(1)).onValidationError(any());
		Mockito.verify(validationListener2, times(1)).onValidationError(any());
		Mockito.verifyNoMoreInteractions(validationListener2);
		Mockito.verifyNoMoreInteractions(validationListener2);
	}

	private HttpServletRequest createRequestWithoutToken() {
		return Mockito.mock(HttpServletRequest.class);
	}

	private HttpServletRequest createRequestWithToken(String bearerAuthorizationHeader) {
		HttpServletRequest httpRequest = createRequestWithoutToken();
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + bearerAuthorizationHeader);
		return httpRequest;
	}

}
