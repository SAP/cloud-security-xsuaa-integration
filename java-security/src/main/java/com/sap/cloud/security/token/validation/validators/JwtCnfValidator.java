package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.x509.X509Parser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Validates if the jwt access token is intended for the OAuth2 client of this
 * application, in certificate based authentication scenario. The cnf claim
 * provides the SHA-256 thumbprint of the X.509 certificate information, this
 * information needs to match the thumbprint of the provided certificate.
 * <p>
 * Validates whether there 'cnf' thumbprint value matches with the X509
 * certificate from the request.
 */
public class JwtCnfValidator implements Validator<Token> {
	private static final Logger LOGGER = LoggerFactory.getLogger(JwtCnfValidator.class);

	/**
	 * Validates the cnf thumbprint of X509 certificate against trusted
	 * certificate's thumbprint.
	 *
	 * In case audience contains only a single value, thumbprint comparison is not
	 * performed and request is validated. To guarantee that this single audience is
	 * trusted, use this validator in combination with {@link JwtAudienceValidator}
	 *
	 * @param token
	 *            token to be validated
	 * @return validation result. Result is valid when both thumbprints match in
	 *         case of multiple audiences.
	 */
	@Override
	public ValidationResult validate(Token token) {

		String cnf = extractCnfThumbprintFromToken(token);
		LOGGER.debug("Cnf thumbprint: {}", cnf);
		if (token.getAudiences().size() == 1) {
			return ValidationResults.createValid();
		} else if (cnf != null) {
			String trustedCertificate = SecurityContext.getCertificate();
			if (trustedCertificate == null) {
				LOGGER.error("X509 certificate missing from SecurityContext");
				return ValidationResults.createInvalid("Certificate validation failed");
			}
			try {
				String trustedX509Thumbprint = X509Parser.getX509Thumbprint(trustedCertificate);
				if (trustedX509Thumbprint.equals(cnf)) {
					return ValidationResults.createValid();
				}
				LOGGER.error("Thumbprint from cnf claim {} != thumbprint from certificate {}", cnf,
						trustedX509Thumbprint);
			} catch (NoSuchAlgorithmException | CertificateException e) {
				LOGGER.error("Couldn't generate x509 thumbprint. {}", e.getMessage(), e);
			}
		}
		return ValidationResults.createInvalid("Certificate validation failed");
	}

	/**
	 * Extract cnf attribute value of 'x5t#S256' (SHA-256 hashed certificate
	 * thumbprint) from token.
	 *
	 * @param token
	 *            received token
	 * @return cnf value of 'x5t#S256' or null if value is not present
	 */
	@Nullable
	private static String extractCnfThumbprintFromToken(Token token) {
		JsonObject cnf = token.getClaimAsJsonObject(TokenClaims.CNF);
		return cnf == null ? null : cnf.getAsString(TokenClaims.X509_THUMBPRINT);
	}

}
