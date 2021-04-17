package com.sap.cloud.security.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

public class X509Parser {
	public static final Logger LOGGER = LoggerFactory.getLogger(X509Parser.class);

	private X509Parser() {
	}

	/**
	 * Generates X509 thumbprint from provided certificate as specified in JWT
	 * Certificate Thumbprint Confirmation Method
	 * 
	 * @see <a href="https://tools.ietf.org/html/rfc8705#section-3.1"></a>
	 * @param certificate
	 *            Base64 encoded X509 certificate
	 * @return Thumbprint of X509 certificate
	 * @throws NoSuchAlgorithmException
	 *             when a particular cryptographic algorithm is requested but is not
	 *             available in the environment
	 * @throws CertificateException
	 *             is thrown if errors occur while decoding X509 certificate
	 */
	public static String getX509Thumbprint(String certificate) throws NoSuchAlgorithmException, CertificateException {
		X509Certificate x509Certificate = decodeX509(
				Objects.requireNonNull(certificate, "X509 certificate can't be null"));
		MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
		byte[] hashedX509 = sha256Digest.digest(x509Certificate.getEncoded());
		String base64UrlEncoding = Base64.getUrlEncoder().encodeToString(hashedX509);
		LOGGER.debug("Base64-url encoded thumbprint: {}", base64UrlEncoding);
		return normalizeThumbprint(base64UrlEncoding);
	}

	/**
	 * Thumbprint generation alternative to {@link #getX509Thumbprint(String)}
	 * without decoding into {@link X509Certificate}class
	 *
	 * @see <a href="https://tools.ietf.org/html/rfc8705#section-3.1"></a>
	 * @param base64certificate
	 *            certificate encoded in Base64, supports also PEM encoded
	 *            certificates
	 * @return Thumbprint of X509 certificate
	 * @throws NoSuchAlgorithmException
	 *             when a particular cryptographic algorithm is requested but is not
	 *             available in the environment
	 */
	public static String getCertificateThumbprint(String base64certificate) throws NoSuchAlgorithmException {
		base64certificate = base64certificate
				.replace("-----BEGIN CERTIFICATE-----", "")
				.replace("-----END CERTIFICATE-----", "")
				.replaceAll("\\s", "");
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] der = Base64.getDecoder().decode(base64certificate.getBytes(StandardCharsets.UTF_8));
		byte[] hashedX509 = sha256.digest(der);
		return normalizeThumbprint(Base64.getUrlEncoder().encodeToString(hashedX509));
	}

	/**
	 * The base64url-encoded value MUST omit all trailing pad '=' characters and
	 * MUST NOT include any line breaks, whitespace, or other additional characters
	 *
	 * @param thumbprint
	 *            raw thumbprint of X509
	 * @return thumbprint without trailing '=' and '\n'
	 */
	static String normalizeThumbprint(String thumbprint) {
		return thumbprint.trim().replaceFirst("=*$", "").replace("\n", "").replace("\\n", "");
	}

	/**
	 * Decodes X509 base64 encoded certificate into X509Certificate class
	 * 
	 * @param encodedX509
	 *            base64 encoded X509 certificate
	 * @return Decoded X509Certificate
	 * @throws CertificateException
	 *             if String value of certificate cannot be parsed
	 */
	private static X509Certificate decodeX509(@Nonnull String encodedX509) throws CertificateException {
		String encodedPemX509 = encodePemLabels(encodedX509);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bytes = new ByteArrayInputStream(encodedPemX509.getBytes(StandardCharsets.UTF_8));

		return (X509Certificate) certFactory.generateCertificate(bytes);
	}

	@Nonnull
	private static String encodePemLabels(String base64EncodedCert) {
		if (!base64EncodedCert.startsWith("-----BEGIN CERTIFICATE-----")) {
			base64EncodedCert = "-----BEGIN CERTIFICATE-----\n" + base64EncodedCert;
		}
		if (!base64EncodedCert.endsWith("-----END CERTIFICATE-----")) {
			base64EncodedCert = base64EncodedCert + "\n-----END CERTIFICATE-----";
		}
		LOGGER.debug("PEM encoded certificate: {}", base64EncodedCert);
		return base64EncodedCert;
	}

}
