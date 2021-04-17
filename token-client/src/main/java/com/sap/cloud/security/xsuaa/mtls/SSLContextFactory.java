package com.sap.cloud.security.xsuaa.mtls;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates a SSLContext (without Bouncy Castle crypto lib).
 *
 */
public class SSLContextFactory {
	private static final char[] noPassword = "".toCharArray();
	private static final SSLContextFactory instance = new SSLContextFactory();
	private Logger logger;

	private SSLContextFactory() {
		logger = LoggerFactory.getLogger(getClass());
	}

	public static SSLContextFactory getInstance() {
		return instance;
	}

	/**
	 * Creates a SSLContext which can be used to parameterize your Rest client, in
	 * order to support mutual TLS.
	 *
	 * @param x509Certificates,
	 *            you can get from your Service Configuration
	 * @param rsaPrivateKey,
	 *            you can get from your Service Configuration
	 * @return a new SSLContext instance
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public SSLContext create(String x509Certificates, String rsaPrivateKey)
			throws GeneralSecurityException, IOException {
		assertHasText(x509Certificates, "x509Certificate is required");
		assertHasText(rsaPrivateKey, "rsaPrivateKey is required");

		SSLContext sslContext = createDefaultSSLContext();

		PrivateKey privateKey = getPrivateKeyFromString(rsaPrivateKey);
		Certificate[] certificateChain = getCertificatesFromString(x509Certificates);

		KeyStore keystore = initializeKeyStore(privateKey, certificateChain);

		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		keyManagerFactory.init(keystore, noPassword);

		sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

		return sslContext;
	}

	private KeyStore initializeKeyStore(PrivateKey privateKey, Certificate[] certificateChain)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore keystore = KeyStore.getInstance("jks");
		keystore.load(null); // there is no data in the keystore file - loads empty keystore
		int i = 0;
		for (Certificate certificate : certificateChain) {
			keystore.setCertificateEntry("cert-alias-" + "" + i++, certificate);
		}
		keystore.setKeyEntry("key-alias", privateKey, noPassword, certificateChain);

		return keystore;
	}

	private SSLContext createDefaultSSLContext() throws NoSuchAlgorithmException {
		return SSLContext.getInstance("TLS");
	}

	private PrivateKey getPrivateKeyFromString(final String rsaPrivateKey) throws GeneralSecurityException {
		String privateKeyPEM = rsaPrivateKey;
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("\n", "");
		privateKeyPEM = privateKeyPEM.replace("\\n", "");
		logger.debug("privateKeyPem: '{}'", privateKeyPEM);

		KeySpec keySpec = parseDERPrivateKey(Base64.getDecoder().decode(privateKeyPEM));

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

		return privateKey;
	}

	private Certificate[] getCertificatesFromString(String certificates) throws CertificateException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		byte[] certificatesBytes = certificates.replace("\\n", "\n").getBytes();

		Collection<Certificate> certificateList = (Collection<Certificate>) factory
				.generateCertificates(new ByteArrayInputStream(certificatesBytes));
		Certificate[] certificateArray = certificateList.toArray(new Certificate[certificateList.size()]);

		return certificateArray;
	}

	private KeySpec parseDERPrivateKey(byte[] privateKeyDerEncoded)
			throws GeneralSecurityException {
		KeySpec keySpec;
		MinimalDERParser parser = new MinimalDERParser(privateKeyDerEncoded);

		try {
			parser.getSequence();

			BigInteger version = parser.getBigInteger();
			if (!version.equals(BigInteger.ZERO)) {
				throw new IllegalArgumentException("Only version 0 supported for PKCS1 decoding.");
			}
			BigInteger modulus = parser.getBigInteger();
			BigInteger publicExponent = parser.getBigInteger();
			BigInteger privateExponent = parser.getBigInteger();
			BigInteger primeP = parser.getBigInteger();
			BigInteger primeQ = parser.getBigInteger();
			BigInteger primeExponentP = parser.getBigInteger();
			BigInteger primeExponentQ = parser.getBigInteger();
			BigInteger crtCoefficient = parser.getBigInteger();

			keySpec = new RSAPrivateCrtKeySpec(
					modulus,
					publicExponent,
					privateExponent,
					primeP,
					primeQ,
					primeExponentP,
					primeExponentQ,
					crtCoefficient);
		} catch (IOException e) {
			logger.error("Exception during parsing DER encoded private key ({})", e.getMessage());
			throw new GeneralSecurityException("Exception during parsing DER encoded private key", e);
		}
		return keySpec;
	}
}
