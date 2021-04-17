package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Validates if the jwt access token is intended for the OAuth2 client of this
 * application. The aud (audience) claim identifies the recipients the JWT is
 * issued for.
 *
 * Validates whether there is one audience that matches one of the configured
 * OAuth2 client ids.
 */
public class JwtAudienceValidator implements Validator<Token> {
	private static final Logger logger = LoggerFactory.getLogger(JwtAudienceValidator.class);
	private static final char DOT = '.';

	private final Set<String> trustedClientIds = new LinkedHashSet<>();

	JwtAudienceValidator(String clientId) {
		configureTrustedClientId(clientId);
	}

	JwtAudienceValidator configureTrustedClientId(String clientId) {
		assertHasText(clientId, "JwtAudienceValidator requires a clientId.");
		trustedClientIds.add(clientId);
		logger.info("configured JwtAudienceValidator with clientId {}.", clientId);

		return this;
	}

	@Override
	public ValidationResult validate(Token token) {
		Set<String> allowedAudiences = extractAudiencesFromToken(token);

		if (validateDefault(allowedAudiences)
				|| validateAudienceOfXsuaaBrokerClone(allowedAudiences)) {
			return ValidationResults.createValid();
		}
		return ValidationResults.createInvalid(
				"Jwt token with audience {} is not issued for these clientIds: {}.",
				token.getAudiences(), trustedClientIds);
	}

	private boolean validateDefault(Set<String> allowedAudiences) {
		for (String configuredClientId : trustedClientIds) {
			if (allowedAudiences.contains(configuredClientId)) {
				return true;
			}
		}
		return false;
	}

	private boolean validateAudienceOfXsuaaBrokerClone(Set<String> allowedAudiences) {
		for (String configuredClientId : trustedClientIds) {
			if (configuredClientId.contains("!b")) {
				for (String audience : allowedAudiences) {
					if (audience.endsWith("|" + configuredClientId)) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Retrieve audiences from token.
	 *
	 * @param token
	 * @return (empty) list of audiences
	 */
	static Set<String> extractAudiencesFromToken(Token token) {
		Set<String> audiences = new LinkedHashSet<>();

		for (String audience : token.getAudiences()) {
			if (audience.contains("" + DOT)) {
				// CF UAA derives the audiences from the scopes.
				// In case the scopes contains namespaces, these needs to be removed.
				String aud = extractAppId(audience);
				if (!aud.isEmpty()) {
					audiences.add(aud);
				}
			} else {
				audiences.add(audience);
			}
		}

		if (token.hasClaim(TokenClaims.AUTHORIZATION_PARTY)) {
			audiences.add(token.getClientId());
		}
		// extract audience (app-id) from scopes
		if (Service.XSUAA.equals(token.getService())) {
			if (token.getAudiences().isEmpty()) {
				for (String scope : token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)) {
					if (scope.contains(".")) {
						audiences.add(extractAppId(scope));
					}
				}
			}
		}
		logger.info("The audiences that are derived from the token: {}.", audiences);
		return audiences;
	}

	/**
	 * In case of audiences, the namespaces are trimmed. In case of scopes, the
	 * namespaces and the scope names are trimmed.
	 *
	 * @param scopeOrAudience
	 * @return
	 */
	static String extractAppId(String scopeOrAudience) {
		return scopeOrAudience.substring(0, scopeOrAudience.indexOf(DOT)).trim();
	}

	public Set<String> getTrustedClientIds() {
		return trustedClientIds;
	}
}
