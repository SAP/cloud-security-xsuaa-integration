/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.BEGIN_PUBLIC_KEY;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.END_PUBLIC_KEY;

class JsonWebKeyImpl implements JsonWebKey {
	private final JwtSignatureAlgorithm keyAlgorithm;
	private final String keyId;
	private final String pemEncodedPublicKey;
	private final String modulus;
	private final String publicExponent;
	private PublicKey publicKey;

	JsonWebKeyImpl(JwtSignatureAlgorithm keyAlgorithm, @Nullable String keyId, String modulus,
			String publicExponent, @Nullable String pemEncodedPublicKey) {
		Assertions.assertNotNull(keyAlgorithm, "keyAlgorithm must be not null");
		this.keyId = keyId != null ? keyId : DEFAULT_KEY_ID;

		this.pemEncodedPublicKey = pemEncodedPublicKey;
		this.publicExponent = publicExponent;
		this.modulus = modulus;
		this.keyAlgorithm = keyAlgorithm;
	}

	@Override
	public JwtSignatureAlgorithm getKeyAlgorithm() {
		return keyAlgorithm;
	}

	@Nullable
	@Override
	public String getId() {
		return keyId;
	}

	@Override
	public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (publicKey != null) {
			return publicKey;
		}
		if (pemEncodedPublicKey != null) {
			publicKey = createPublicKeyFromPemEncodedPublicKey(keyAlgorithm, pemEncodedPublicKey);
		} else if (keyAlgorithm.type().equalsIgnoreCase("RSA")) {
			publicKey = createRSAPublicKey(publicExponent, modulus);
		} else {
			throw new IllegalStateException("JWT token with web key type " + keyAlgorithm + " can not be verified.");
		}
		return publicKey;
	}

	static PublicKey createRSAPublicKey(String publicExponent, String modulus)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(modulus));
		BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(publicExponent));
		KeySpec keySpec = new RSAPublicKeySpec(n, e);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(keySpec);
	}

	public static PublicKey createPublicKeyFromPemEncodedPublicKey(JwtSignatureAlgorithm algorithm,
			String pemEncodedKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] decodedBytes = Base64.getMimeDecoder().decode(convertPEMKey(pemEncodedKey));

		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(decodedBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm.type());
		return keyFactory.generatePublic(keySpecX509);
	}

	public static String convertPEMKey(String pemEncodedKey) {
		String key = pemEncodedKey;
		key = key.replace(BEGIN_PUBLIC_KEY, "");
		key = key.replace(END_PUBLIC_KEY, "");
		return key;
	}

	@Override
	public int hashCode() {
		return Objects.hash(keyAlgorithm, keyId != null ? keyId : DEFAULT_KEY_ID);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;

		JsonWebKeyImpl that = (JsonWebKeyImpl) o;

		if (getKeyAlgorithm() != that.getKeyAlgorithm())
			return false;
		return keyId.equals(that.keyId);
	}

}
