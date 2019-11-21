package com.sap.cloud.security.xsuaa.jwk;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class JsonWebKeySetFactoryTest {

	private String jsonWebTokenKeys;

	@Before
	public void setup() throws IOException {
		jsonWebTokenKeys = IOUtils.resourceToString("/JsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Test
	public void getEmptyJsonWebKeySetWhenJsonIsNull() {
		assertThat(JsonWebKeySetFactory.createFromJson(null).getAll(), equalTo(Collections.EMPTY_SET));
	}

	@Test
	public void getKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByTypeAndId(JsonWebKey.Type.RSA, "key-id-1");
		assertThat(jwk.getAlgorithm(), equalTo("RS256"));
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getKeys() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByTypeAndId(JsonWebKey.Type.RSA, "key-id-1");
		assertThat(jwk.getAlgorithm(), equalTo("RS256"));
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getIasKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		jsonWebTokenKeys = IOUtils.resourceToString("/iasJsonWebTokenKeys.json", StandardCharsets.UTF_8);
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByTypeAndId(JsonWebKey.Type.RSA, null);
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo(JsonWebKey.DEFAULT_KEY_ID));
	}
}