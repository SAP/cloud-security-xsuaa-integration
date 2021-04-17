package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public abstract class AbstractTokenAuthenticator implements TokenAuthenticator {

	private static final Logger logger = LoggerFactory.getLogger(AbstractTokenAuthenticator.class);
	private final List<ValidationListener> validationListeners = new ArrayList<>();
	Validator<Token> tokenValidator;
	protected CloseableHttpClient httpClient;
	protected OAuth2ServiceConfiguration serviceConfiguration;
	private CacheConfiguration tokenKeyCacheConfiguration;

	@Override
	public TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response) {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
			if (headerIsAvailable(authorizationHeader)) {
				try {
					Token token = Token.create(authorizationHeader);
					return tokenValidationResult(token);
				} catch (Exception e) {
					return unauthenticated("Unexpected error occurred: " + e.getMessage());
				}
			} else {
				return unauthenticated("Authorization header is missing.");
			}
		}
		return TokenAuthenticatorResult.createUnauthenticated("Could not process request " + request);
	}

	/**
	 * Use to configure the token key cache.
	 *
	 * @param cacheConfiguration
	 *            the cache configuration
	 * @return this authenticator
	 */
	public AbstractTokenAuthenticator withCacheConfiguration(CacheConfiguration cacheConfiguration) {
		this.tokenKeyCacheConfiguration = cacheConfiguration;
		return this;
	}

	/**
	 * Use to configure the HttpClient that is used to retrieve token keys.
	 *
	 * @param httpClient
	 *            the HttpClient
	 * @return this authenticator
	 */
	public AbstractTokenAuthenticator withHttpClient(CloseableHttpClient httpClient) {
		this.httpClient = httpClient;
		return this;
	}

	/**
	 * Use to override the service configuration used.
	 *
	 * @param serviceConfiguration
	 *            the service configuration to use
	 * @return this authenticator
	 */
	public AbstractTokenAuthenticator withServiceConfiguration(OAuth2ServiceConfiguration serviceConfiguration) {
		this.serviceConfiguration = serviceConfiguration;
		setupTokenFactory();
		return this;
	}

	private void setupTokenFactory() {
		if (serviceConfiguration.getService() == Service.XSUAA) {
			HybridTokenFactory.withXsuaaAppId(serviceConfiguration.getProperty(CFConstants.XSUAA.APP_ID));
		}
	}

	/**
	 * Adds the validation listener to the jwt validator that is being used by the
	 * authenticator to validate the tokens.
	 *
	 * @param validationListener
	 *            the listener to be added.
	 * @return the authenticator instance
	 */
	public AbstractTokenAuthenticator withValidationListener(ValidationListener validationListener) {
		this.validationListeners.add(validationListener);
		return this;
	}

	/**
	 * Return configured service configuration or Environments.getCurrent() if not
	 * configured.
	 *
	 * @return the actual service configuration
	 * @throws IllegalStateException
	 *             in case service configuration is null
	 */
	protected abstract OAuth2ServiceConfiguration getServiceConfiguration();

	/**
	 * Return other configured service configurations or null if not configured.
	 *
	 * @return the other service configuration or null
	 */
	@Nullable
	protected abstract OAuth2ServiceConfiguration getOtherServiceConfiguration();

	/**
	 * Extracts the {@link Token} from the authorization header.
	 *
	 * @param authorizationHeader
	 *            the value of the 'Authorization' request header
	 * @return the {@link Token} instance.
	 */
	protected abstract Token extractFromHeader(String authorizationHeader);

	Validator<Token> getOrCreateTokenValidator() {
		if (this.tokenValidator == null) {
			this.tokenValidator = getJwtValidatorBuilder().build();
		}
		return this.tokenValidator;
	}

	JwtValidatorBuilder getJwtValidatorBuilder() {
		JwtValidatorBuilder jwtValidatorBuilder = JwtValidatorBuilder.getInstance(getServiceConfiguration())
				.withHttpClient(httpClient);
		jwtValidatorBuilder.configureAnotherServiceInstance(getOtherServiceConfiguration());
		Optional.ofNullable(tokenKeyCacheConfiguration).ifPresent(jwtValidatorBuilder::withCacheConfiguration);
		validationListeners.forEach(jwtValidatorBuilder::withValidatorListener);
		return jwtValidatorBuilder;
	}

	TokenAuthenticationResult unauthenticated(String message) {
		logger.warn("Request could not be authenticated: {}.", message);
		return TokenAuthenticatorResult.createUnauthenticated(message);
	}

	protected TokenAuthenticationResult authenticated(Token token) {
		return TokenAuthenticatorResult.createAuthenticated(Collections.emptyList(), token);
	}

	boolean headerIsAvailable(String authorizationHeader) {
		return authorizationHeader != null && !authorizationHeader.isEmpty();
	}

	TokenAuthenticationResult tokenValidationResult(Token token) {
		Validator<Token> validator = getOrCreateTokenValidator();
		ValidationResult result = validator.validate(token);
		if (result.isValid()) {
			SecurityContext.setToken(token);
			return authenticated(token);
		} else {
			return unauthenticated("Error during token validation: " + result.getErrorDescription());
		}
	}

}
