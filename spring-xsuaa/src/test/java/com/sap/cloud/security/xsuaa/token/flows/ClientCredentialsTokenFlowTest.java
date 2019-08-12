package com.sap.cloud.security.xsuaa.token.flows;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sap.cloud.security.xsuaa.backend.OAuth2Service;
import com.sap.cloud.security.xsuaa.backend.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.backend.XsuaaDefaultEndpoints;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.buildAdditionalAuthoritiesJson;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ClientCredentialsTokenFlowTest {

	private OAuth2TokenService tokenService;
	private VariableKeySetUriTokenDecoder tokenDecoder;
	private TokenDecoderMock tokenDecoderMock;
	private Jwt mockJwt;
	private String clientId = "clientId";
	private String clientSecret = "clientSecret";

	@Before
	public void setup() {
		this.tokenService = new OAuth2Service(new RestTemplate());
		this.tokenDecoder = new NimbusTokenDecoder();

		this.mockJwt = buildMockJwt();
		this.tokenDecoderMock = new TokenDecoderMock(mockJwt);
	}

	private Jwt buildMockJwt() {
		Map<String, Object> jwtHeaders = new HashMap<String, Object>();
		jwtHeaders.put("dummyHeader", "dummyHeaderValue");

		Map<String, Object> jwtClaims = new HashMap<String, Object>();
		jwtClaims.put("dummyClaim", "dummyClaimValue");

		return new Jwt("mockJwtValue", Instant.now(),
				Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
	}

	@Test
	public void test_constructor_withBaseURI() throws TokenFlowException {
		createTokenFlow();
	}

	private ClientCredentialsTokenFlow createTokenFlow() {
		return new ClientCredentialsTokenFlow(tokenService, tokenDecoder,
				new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
	}

	@Test
	public void test_constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new ClientCredentialsTokenFlow(null, tokenDecoder, new
					XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new ClientCredentialsTokenFlow(tokenService, null, new
					XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("TokenDecoder");

		assertThatThrownBy(() -> {
			new ClientCredentialsTokenFlow(tokenService, tokenDecoder, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");
	}

	@Test
	public void test_execute_throwsIfMandatoryFieldsNotSet() {

		assertThatThrownBy(() -> {
			ClientCredentialsTokenFlow tokenFlow = createTokenFlow();
			tokenFlow.client(null)
					.secret(TestConstants.clientSecret)
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client ID");

		assertThatThrownBy(() -> {
			ClientCredentialsTokenFlow tokenFlow = createTokenFlow();
			tokenFlow.client(TestConstants.clientId)
					.secret(null)
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client secret");

		assertThatThrownBy(() -> {
			ClientCredentialsTokenFlow tokenFlow = createTokenFlow();
			tokenFlow.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("Client credentials flow request is not valid");
	}

	@Test
	public void test_execute() throws TokenFlowException {

		HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId,
				clientSecret);

		URI expectedURI =
				UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
						.queryParam("grant_type", "client_credentials").build().toUri();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedURI,
				expectedRequest, Map.class,
				mockJwt.getTokenValue(), HttpStatus.OK);

		ClientCredentialsTokenFlow tokenFlow = new
				ClientCredentialsTokenFlow(new OAuth2Service(restTemplateMock), tokenDecoderMock,
				new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));

		tokenFlow.client(clientId)
				.secret(clientSecret)
				.execute();

		restTemplateMock.validateCallstate();
		tokenDecoderMock.validateCallstate();
	}

	@Test
	public void test_execute_throwsIfHttpStatusUnauthorized() {

		HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId,
				clientSecret);
		URI expectedURI =
				UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
						.queryParam("grant_type", "client_credentials").build().toUri();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedURI,
				expectedRequest, Map.class,
				mockJwt.getTokenValue(), HttpStatus.UNAUTHORIZED);

		ClientCredentialsTokenFlow tokenFlow = new
				ClientCredentialsTokenFlow(new OAuth2Service(restTemplateMock), tokenDecoderMock,
				new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));

		assertThatThrownBy(() -> {
			tokenFlow.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(String.format("Received status code %s",
						HttpStatus.UNAUTHORIZED));
	}

	@Test
	public void test_execute_throwsIfHttpStatusIsNotOK() {

		HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId,
				clientSecret);
		URI expectedURI =
				UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
						.queryParam("grant_type", "client_credentials").build().toUri();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedURI,
				expectedRequest, Map.class,
				mockJwt.getTokenValue(), HttpStatus.CONFLICT);

		ClientCredentialsTokenFlow tokenFlow = new
				ClientCredentialsTokenFlow(new OAuth2Service(restTemplateMock), tokenDecoderMock,
				new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));

		assertThatThrownBy(() -> {
			tokenFlow.client(clientId)
					.secret(clientSecret)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(String.format("Received status code %s",
						HttpStatus.CONFLICT));
	}

	@Test
	public void test_execute_withAdditionalAuthorities() throws
			TokenFlowException, JsonProcessingException {

		HttpEntity<Void> expectedRequest = buildExpectedRequest(clientId,
				clientSecret);

		Map<String, String> additionalAuthorities = new HashMap<String, String>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");
		String authorities = buildAdditionalAuthoritiesJson(additionalAuthorities);
		// returns JSON!

		URI expectedURI =
				UriComponentsBuilder.fromUri(TestConstants.tokenEndpointUri)
						.queryParam("grant_type", "client_credentials")
						.queryParam("authorities", authorities)
						.build()
						.encode()
						.toUri();

		RestTemplateMock restTemplateMock = new RestTemplateMock(expectedURI,
				expectedRequest, Map.class,
				mockJwt.getTokenValue(), HttpStatus.OK);

		ClientCredentialsTokenFlow tokenFlow = new
				ClientCredentialsTokenFlow(new OAuth2Service(restTemplateMock), tokenDecoderMock,
				new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
		tokenFlow.client(clientId)
				.secret(clientSecret)
				.attributes(additionalAuthorities)
				.execute();

		restTemplateMock.validateCallstate();
		tokenDecoderMock.validateCallstate();
	}

	private HttpEntity<Void> buildExpectedRequest(String clientId, String
			clientSecret) {
		HttpHeaders headers = new HttpHeaders();
		headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
		headers.add("Authorization", "Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0");
		HttpEntity<Void> expectedRequest = new HttpEntity<>(headers);
		return expectedRequest;
	}
}
