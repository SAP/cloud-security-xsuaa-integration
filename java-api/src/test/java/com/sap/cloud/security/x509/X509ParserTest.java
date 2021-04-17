package com.sap.cloud.security.x509;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static com.sap.cloud.security.x509.X509Parser.getX509Thumbprint;
import static com.sap.cloud.security.x509.X509Parser.normalizeThumbprint;

class X509ParserTest {

	private static String x509;
	private static final String cnf = "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM";

	@BeforeAll
	static void beforeAll() throws IOException {
		x509 = IOUtils.resourceToString("/cf-forwarded-client-cert.txt", StandardCharsets.UTF_8);
	}

	@Test
	void normalizeThumbprintTest() throws NoSuchAlgorithmException, CertificateException {
		String normalizedX509 = normalizeThumbprint(getX509Thumbprint(x509));
		Assertions.assertFalse(normalizedX509.endsWith("="));
		Assertions.assertFalse(normalizedX509.contains("\n"));
	}

	@Test
	void getX509ThumbprintTest() throws NoSuchAlgorithmException, CertificateException {
		Assertions.assertEquals(cnf, getX509Thumbprint(x509));
	}

	@Test
	void getJwtThumbprintTest() throws NoSuchAlgorithmException {
		Assertions.assertEquals(cnf, X509Parser.getCertificateThumbprint(x509));
	}

	@Test
	void testRegex() {
		String testCase = "I\nDon't\nWant\r\nTo Be\r On New Line";
		String result = testCase.replaceAll("\\s", "");
		Assertions.assertEquals("IDon'tWantToBeOnNewLine", result);
	}
}