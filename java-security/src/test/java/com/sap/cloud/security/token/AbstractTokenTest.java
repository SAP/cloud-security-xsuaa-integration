/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import org.apache.commons.io.IOUtils;
import org.assertj.core.util.Lists;
import org.assertj.core.util.Sets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static com.sap.cloud.security.token.TokenClaims.AUTHORIZATION_PARTY;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.CLIENT_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

public class AbstractTokenTest {

	private final String jwtString;
	private Token cut;

	public AbstractTokenTest() throws IOException {
		jwtString = IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		cut = new AbstractToken(jwtString) {
			@Override
			public Principal getPrincipal() {
				return null;
			}

			@Override
			public Service getService() {
				return null;
			}
		};
	}

	@Test
	public void getHeaderParameterAsString() {
		assertThat(cut.getHeaderParameterAsString("alg")).isEqualTo("RS256");
	}

	@Test
	public void containsClaim() {
		assertThat(cut.hasClaim("notContained")).isFalse();
		assertThat(cut.hasClaim("grant_type")).isTrue();
	}

	@Test
	public void getClaimAsString() {
		assertThat(cut.getClaimAsString("zid")).isEqualTo("uaa");
	}

	@Test
	public void getClaimAsStringList() {
		assertThat(cut.getClaimAsStringList("aud")).containsExactly("uaa", "sap_osb");
	}

	@Test
	public void getClaimAsStringList_unknownClaim_emptyList() {
		assertThat(cut.getClaimAsStringList("anything")).isEqualTo(Collections.emptyList());
	}

	@Test
	public void getExpiration() {
		assertThat(cut.getExpiration()).isEqualTo(Instant.ofEpochSecond(1572060769L));
	}

	@Test
	public void tokenWithExpirationInTheFuture_isNotExpired() {
		AbstractToken doesNotExpireSoon = new MockTokenBuilder().withExpiration(MockTokenBuilder.NO_EXPIRE_DATE)
				.build();
		when(doesNotExpireSoon.isExpired()).thenCallRealMethod();

		assertThat(doesNotExpireSoon.isExpired()).isFalse();
	}

	@Test
	public void tokenWithExpirationInThePast_isExpired() {
		assertThat(cut.isExpired()).isTrue();
	}

	@Test
	public void tokenWithoutExpirationDate_isExpired() {
		AbstractToken tokenWithoutExpiration = new MockTokenBuilder().withExpiration(null).build();
		when(tokenWithoutExpiration.isExpired()).thenCallRealMethod();

		assertThat(tokenWithoutExpiration.isExpired()).isTrue();
	}

	@Test
	public void tokenWithLongExpiration_isNotExpired() {
		AbstractToken tokenWithNoExpiration = new MockTokenBuilder().withExpiration(MockTokenBuilder.NO_EXPIRE_DATE)
				.build();
		when(tokenWithNoExpiration.isExpired()).thenCallRealMethod();

		assertThat(tokenWithNoExpiration.isExpired()).isFalse();
	}

	@Test
	public void getNotBefore_notContained_shouldBeNull() {
		assertThat(String.valueOf(cut.getNotBefore().toEpochMilli())).startsWith("1572017569"); // consider iat
	}

	@Test
	public void getTokenValue() {
		assertThat(cut.getTokenValue()).isEqualTo(jwtString);
	}

	@Test
	public void getJsonObject() {
		JsonObject externalAttributes = cut.getClaimAsJsonObject(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE);
		assertThat(externalAttributes.getAsString(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ENHANCER)).isEqualTo("XSUAA");
	}

	@Test
	public void getJsonObject_claimsIsNotAnObject_throwsException() {
		assertThatThrownBy(() -> cut.getClaimAsJsonObject("client_id")).isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void getJsonObject_claimsDoesNotExist_isNull() {
		assertThat(cut.getClaimAsJsonObject("doesNotExist")).isNull();
	}

	@Test
	public void toString_doesNotContainEncodedToken() {
		assertThat(cut.toString()).doesNotContain(cut.getTokenValue());
	}

	@Test
	public void toString_containsTokenContent() {
		assertThat(cut.toString())
				.contains(cut.getHeaderParameterAsString(TokenHeader.JWKS_URL))
				.contains(cut.getHeaderParameterAsString(TokenHeader.KEY_ID))
				.contains(cut.getAudiences())
				.contains(cut.getClientId())
				.contains(cut.getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE))
				.contains(cut.getClaimAsStringList(TokenClaims.XSUAA.SCOPES));
	}

	@Test
	public void isXsuaaToken() {
		assertThat(((AbstractToken) cut).isXsuaaToken()).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "cid", "", "    " })
	public void getClientIdWithCidTest(String cid) throws InvalidTokenException {
		AbstractToken token = Mockito.mock(AbstractToken.class);
		when(token.getAudiences()).thenReturn(Collections.emptySet());
		when(token.getClaimAsString(AUTHORIZATION_PARTY)).thenReturn(null);
		when(token.getClaimAsString(CLIENT_ID)).thenReturn(cid);
		when(token.hasClaim(CLIENT_ID)).thenReturn(!cid.trim().isEmpty());
		when(token.getClientId()).thenCallRealMethod();
		try {
			assertThat(token.getClientId()).isEqualTo(cid);
		} catch (InvalidTokenException e) {
			assertThatThrownBy(() -> token.getClientId()).isExactlyInstanceOf(InvalidTokenException.class);
		}
	}

	@ParameterizedTest
	@MethodSource("clientIdTestArguments")
	public void getClientIdTest(String azp, Set<String> aud, String expectedClientId,
			Class<InvalidTokenException> expectedException) throws InvalidTokenException {
		AbstractToken token = Mockito.mock(AbstractToken.class);
		when(token.getAudiences()).thenReturn(aud);
		when(token.getClaimAsString(AUTHORIZATION_PARTY)).thenReturn(azp);
		when(token.getClientId()).thenCallRealMethod();

		if (expectedException != null) {
			assertThatThrownBy(() -> token.getClientId()).isExactlyInstanceOf(expectedException);
		} else {
			assertThat(token.getClientId()).isEqualTo(expectedClientId);
		}
	}

	@ParameterizedTest
	@MethodSource("audienceTestArguments")
	public void getAudiencesTest(String azp, List<String> aud, Set<String> expectedAudiences,
			boolean hasAzpClaim) throws InvalidTokenException {
		AbstractToken token = Mockito.mock(AbstractToken.class);
		when(token.hasClaim(AUTHORIZATION_PARTY)).thenReturn(hasAzpClaim);
		when(token.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(aud);
		when(token.getClaimAsString(AUTHORIZATION_PARTY)).thenReturn(azp);
		when(token.getAudiences()).thenCallRealMethod();

		assertThat(token.getAudiences()).isEqualTo(expectedAudiences);
	}

	private static Stream<Arguments> audienceTestArguments() {
		return Stream.of(
				Arguments.of("azp", Lists.newArrayList("aud1", "aud2"), Sets.newLinkedHashSet("aud1", "aud2"), true),
				Arguments.of("azp", Lists.newArrayList("aud"), Sets.newLinkedHashSet("aud"), true),
				Arguments.of("azp", Lists.newArrayList(), Sets.newLinkedHashSet("azp"), true),
				Arguments.of("", Arrays.asList("aud1", "aud2"), Sets.newLinkedHashSet("aud1", "aud2"), true),
				Arguments.of("", Arrays.asList("aud"), Sets.newLinkedHashSet("aud"), true),
				Arguments.of("", Arrays.asList(), Sets.newLinkedHashSet(""), true),
				Arguments.of(null, Arrays.asList("aud"), Sets.newLinkedHashSet("aud"), false),
				Arguments.of(null, Arrays.asList("aud1", "aud2"), Sets.newLinkedHashSet("aud1", "aud2"), false),
				Arguments.of(null, Arrays.asList(), Sets.newLinkedHashSet(), false));
	}

	private static Stream<Arguments> clientIdTestArguments() {
		return Stream.of(
				Arguments.of("azp", Sets.newLinkedHashSet("aud1", "aud2"), "azp", null),
				Arguments.of("azp", Sets.newLinkedHashSet("aud"), "azp", null),
				Arguments.of("", Sets.newLinkedHashSet("aud1", "aud2"), null, InvalidTokenException.class),
				Arguments.of("", Sets.newLinkedHashSet("aud"), "aud", null),
				Arguments.of("", Sets.newLinkedHashSet(), null, InvalidTokenException.class),
				Arguments.of(null, Sets.newLinkedHashSet("aud"), "aud", null),
				Arguments.of(null, Sets.newLinkedHashSet("aud1", "aud2"), null, InvalidTokenException.class),
				Arguments.of(null, Sets.newLinkedHashSet(), null, InvalidTokenException.class),
				Arguments.of("   ", Sets.newLinkedHashSet("aud"), "aud", null),
				Arguments.of("   ", Sets.newLinkedHashSet("aud1", "aud2"), null, InvalidTokenException.class),
				Arguments.of("   ", Sets.newLinkedHashSet(), null, InvalidTokenException.class));
	}
}