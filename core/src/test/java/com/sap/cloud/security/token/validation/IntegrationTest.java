package com.sap.cloud.security.token.validation;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFEnvParser;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;

public class IntegrationTest {

	@Test
	public void validationFails_withXsuaaCombiningValidator() throws URISyntaxException, IOException {
		OAuth2ServiceConfiguration configuration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getDomain()).thenReturn("auth.com");
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty(CFConstants.APP_ID)).thenReturn("test-app!t123");

		Validator combiningValidator = CombiningValidator.builderFor(configuration).build();

		Token xsuaaToken = new TokenImpl(
				IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8));
		ValidationResult result = combiningValidator.validate(xsuaaToken);
		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrorDescription()).contains("Jwt expired at 2019-10-26T03:32:49Z");
	}

	@Test
	@Ignore // TODO
	public void validate_withXsuaaCombiningValidator_whenOAuthServerIsMocked() throws IOException {
		String singleBindingJsonString = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
		CFEnvParser envParser = new CFEnvParser(singleBindingJsonString);
		OAuth2ServiceConfiguration configuration = envParser.load(CFConstants.ServiceType.XSUAA);

		OAuth2TokenKeyService tokenKeyService = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyService.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8)));

		Validator combiningValidator = CombiningValidator.builderFor(configuration)
				.withOAuth2TokenKeyService(tokenKeyService)
				.build();

		Token xsuaaToken = new TokenImpl(
				IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8));

		ValidationResult result = combiningValidator.validate(xsuaaToken);
		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrorDescription())
				.contains("Error retrieving Json Web Keys from Identity Service (https://my.auth.com/token_keys)");
	}
}