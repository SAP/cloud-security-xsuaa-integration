/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;

import com.github.benmanes.caffeine.cache.Ticker;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

public class OAuth2TokenKeyServiceWithCacheTest {

	public static final TokenKeyCacheConfiguration CACHE_CONFIGURATION = TokenKeyCacheConfiguration
			.defaultConfiguration();

	OAuth2TokenKeyServiceWithCache cut;
	OAuth2TokenKeyService tokenKeyServiceMock;
	URI TOKEN_KEYS_URI = URI.create("https://myauth.com/jwks_uri");
	String ZONE_ID = "zone_uuid";
	private TestCacheTicker testCacheTicker;

	@Before
	public void setup() throws IOException {
		tokenKeyServiceMock = mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(eq(TOKEN_KEYS_URI), any()))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));

		testCacheTicker = new TestCacheTicker();
		cut = createCut(CACHE_CONFIGURATION);
	}

	@Test
	public void getFreshInstance() {
		assertThat(cut).isNotSameAs(OAuth2TokenKeyServiceWithCache.getInstance());
	}

	@Test
	public void changeCacheConfiguration() {
		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofSeconds(678), 1234, false));

		assertThat(cut.getCacheConfiguration().getCacheSize()).isEqualTo(1234);
		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(Duration.ofSeconds(678));
	}

	@Test
	public void changeCacheConfiguration_valuesTooLow_leftUnchanged() {
		Duration oldCacheDuration = cut.getCacheConfiguration().getCacheDuration();
		int oldCacheSize = cut.getCacheConfiguration().getCacheSize();

		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofSeconds(1), 1, false));

		assertThat(cut.getCacheConfiguration().getCacheSize()).isEqualTo(oldCacheSize);
		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(oldCacheDuration);
	}

	@Test
	public void changeCacheConfiguration_tooLongDuration_leftUnchanged() {
		Duration oldCacheDuration = cut.getCacheConfiguration().getCacheDuration();

		cut = cut.withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(Duration.ofMinutes(16), 601, false));

		assertThat(cut.getCacheConfiguration().getCacheDuration()).isEqualTo(oldCacheDuration);
	}

	@Test
	public void retrieveTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);

		assertThat(String.valueOf(key.getAlgorithm())).isEqualTo("RSA");
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), eq(ZONE_ID));
	}

	@Test
	public void getCachedTokenKeys() throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);
		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);

		assertThat(cachedKey).isNotNull();
		assertThat(cachedKey).isSameAs(key);
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), any());
	}

	@Test
	public void retrieveNoTokenKeys_returnsNull()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.withTokenKeyService(mock(OAuth2TokenKeyService.class));
		PublicKey key = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);

		assertThat(key).isNull();
	}

	@Test
	public void requestFails_throwsException() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));

		assertThatThrownBy(() -> {
			cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);
		}).isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Currently unavailable");
	}

	@Test
	public void retrieveTokenKeys_afterCacheWasCleared()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, null);
		cut.clearCache();
		PublicKey cachedKey = cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, null);

		assertThat(cachedKey).isNotNull();
		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), eq(null));
	}

	@Test
	public void retrieveTokenKeys_doesRequestKeysAgainAfterCacheExpired()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);
		testCacheTicker.advance(CACHE_CONFIGURATION.getCacheDuration()); // just expired
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);

		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), eq(ZONE_ID));
	}

	@Test
	public void cacheStatistics_isDisabled_statisticsObjectIsNull() {
		cut = createCut(TokenKeyCacheConfiguration
				.getInstance(CACHE_CONFIGURATION.getCacheDuration(), CACHE_CONFIGURATION.getCacheSize(), false));

		assertThat(cut.getCacheStatistics()).isNull();
	}

	@Test
	public void cacheStatistics_isEnabled_returnsStatisticsObject() {
		cut = createCut(TokenKeyCacheConfiguration
				.getInstance(CACHE_CONFIGURATION.getCacheDuration(), CACHE_CONFIGURATION.getCacheSize(), true));

		assertThat(cut.getCacheStatistics()).isInstanceOf(CacheStats.class);
	}

	@Test
	public void retrieveTokenKeysForNewKeyId()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "not-seen-yet", TOKEN_KEYS_URI, ZONE_ID);

		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq(ZONE_ID));
	}

	@Test
	public void retrieveTokenKeysForNewZoneId()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID + "-2");

		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), any());
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq(ZONE_ID));
		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq(ZONE_ID + "-2"));
	}

	@Test
	public void retrieveTokenKeysForAnotherInvalidZoneId()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), eq("invalid-zone")))
				.thenThrow(new OAuth2ServiceException("Invalid zone_uuid provided"));
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);

		assertThatThrownBy(() -> {
			cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, "invalid-zone");
		}).isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Invalid");
		assertThatThrownBy(() -> {
			cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, "invalid-zone");
		}).isInstanceOf(OAuth2ServiceException.class).hasMessageStartingWith("Invalid");

		verify(tokenKeyServiceMock, times(1)).retrieveTokenKeys(any(), eq("invalid-zone"));
	}

	@Test
	public void retrieveTokenKeysForNewEndpoint()
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI, ZONE_ID);
		cut.getPublicKey(JwtSignatureAlgorithm.RS256, "key-id-0", URI.create("http://another/url"), ZONE_ID);

		verify(tokenKeyServiceMock, times(2)).retrieveTokenKeys(any(), eq(ZONE_ID));
	}

	private OAuth2TokenKeyServiceWithCache createCut(TokenKeyCacheConfiguration cacheConfiguration) {
		return OAuth2TokenKeyServiceWithCache
				.getInstance(testCacheTicker)
				.withTokenKeyService(tokenKeyServiceMock)
				.withCacheConfiguration(cacheConfiguration);
	}

	private class TestCacheTicker implements Ticker {
		long elapsed = 0;

		@Override
		public long read() {
			return elapsed;
		}

		public void advance(Duration duration) {
			this.elapsed = elapsed + duration.toNanos();
		}
	}
}
