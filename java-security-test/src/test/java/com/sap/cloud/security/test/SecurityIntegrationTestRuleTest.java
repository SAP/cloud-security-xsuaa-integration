package com.sap.cloud.security.test;

import com.sap.cloud.security.xsuaa.jwk.JsonWebKeyConstants;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Rule;
import org.junit.Test;
import wiremock.org.apache.http.HttpStatus;
import wiremock.org.apache.http.client.methods.CloseableHttpResponse;
import wiremock.org.apache.http.client.methods.HttpGet;
import wiremock.org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;

public class SecurityIntegrationTestRuleTest {

	private static final int PORT = 8484;
	private static final int APPLICATION_SERVER_PORT = 8383;

	private final RSAKeys rsaKeys = RSAKeys.generate();

	@Rule
	public SecurityIntegrationTestRule rule = SecurityIntegrationTestRule.getInstance(XSUAA)
			.setPort(PORT)
			.setKeys(rsaKeys)
			.useApplicationServer("src/test/webapp", APPLICATION_SERVER_PORT);

	public SecurityIntegrationTestRuleTest() {
		rule.getPreconfiguredJwtGenerator().withHeaderParameter("test", "abc123");
	}

	@Test
	public void getTokenKeysRequest_() throws IOException {
		HttpGet httpGet = new HttpGet("http://localhost:" + PORT + "/token_keys");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			String content = readContent(response);
			JSONArray tokenKeys = new JSONObject(content).getJSONArray(JsonWebKeyConstants.KEYS_PARAMETER_NAME);
			assertThat(tokenKeys).hasSize(1);
			assertThat(tokenKeys.get(0)).isInstanceOf(JSONObject.class);
			JSONObject tokenKeyObject = (JSONObject) tokenKeys.get(0);
			String encodedPublicKey = Base64.getEncoder().withoutPadding().encodeToString(rsaKeys.getPublic().getEncoded());
			assertThat(tokenKeyObject.get(JsonWebKeyConstants.VALUE_PARAMETER_NAME)).isEqualTo(encodedPublicKey);
		}
	}

	private String readContent(CloseableHttpResponse response) throws IOException {
		return IOUtils.readLines(response.getEntity().getContent(), StandardCharsets.UTF_8).stream()
						.collect(Collectors.joining());
	}
}