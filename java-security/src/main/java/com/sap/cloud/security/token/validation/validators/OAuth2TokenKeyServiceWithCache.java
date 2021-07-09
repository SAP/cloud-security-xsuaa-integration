/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decorates {@link OAuth2TokenKeyService} with a cache, which gets looked up
 * before the identity service is requested via http.
 */
class OAuth2TokenKeyServiceWithCache implements Cacheable {
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2TokenKeyServiceWithCache.class);

	private OAuth2TokenKeyService tokenKeyService;
	private Cache<String, JsonWebKeySet> cache;
	private CacheConfiguration cacheConfiguration = TokenKeyCacheConfiguration.defaultConfiguration();
	private Ticker cacheTicker;

	private OAuth2TokenKeyServiceWithCache() {
		// use getInstance factory method
	}

	/**
	 * Creates a new instance.
	 *
	 * @return the new instance.
	 */
	public static OAuth2TokenKeyServiceWithCache getInstance() {
		OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
		instance.cacheTicker = Ticker.systemTicker();
		return instance;
	}

	/**
	 * Creates a new instance and sets the cache ticker. This is used for testing.
	 *
	 * @param cacheTicker
	 *            ticker the cache uses to determine time
	 *
	 * @return the new instance.
	 */
	static OAuth2TokenKeyServiceWithCache getInstance(Ticker cacheTicker) {
		OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
		instance.cacheTicker = cacheTicker;
		return instance;
	}

	/**
	 * Caches the Json web keys. Overwrite the cache time (default: 600 seconds).
	 *
	 * @deprecated in favor of {@link #withCacheConfiguration(CacheConfiguration)}
	 * @param timeInSeconds
	 *            time to cache the signing keys
	 * @return this
	 */
	@Deprecated
	public OAuth2TokenKeyServiceWithCache withCacheTime(int timeInSeconds) {
		withCacheConfiguration(TokenKeyCacheConfiguration
				.getInstance(Duration.ofSeconds(timeInSeconds), this.cacheConfiguration.getCacheSize(), false));
		return this;
	}

	/**
	 * Caches the Json web keys. Overwrite the size of the cache (default: 1000).
	 *
	 * @deprecated in favor of {@link #withCacheConfiguration(CacheConfiguration)}
	 * @param size
	 *            number of cached json web keys.
	 * @return this
	 */
	@Deprecated
	public OAuth2TokenKeyServiceWithCache withCacheSize(int size) {
		withCacheConfiguration(TokenKeyCacheConfiguration
				.getInstance(cacheConfiguration.getCacheDuration(), size, false));
		return this;
	}

	/**
	 * Configures the token key cache. Use
	 * {@link TokenKeyCacheConfiguration#getInstance(Duration, int, boolean)} to
	 * pass a custom configuration.
	 *
	 * Note that the cache size must be 1000 or more and the cache duration must be
	 * at least 600 seconds!
	 *
	 * @param cacheConfiguration
	 *            the cache configuration
	 * @return this tokenKeyServiceWithCache
	 */
	public OAuth2TokenKeyServiceWithCache withCacheConfiguration(CacheConfiguration cacheConfiguration) {
		this.cacheConfiguration = getCheckedConfiguration(cacheConfiguration);
		LOGGER.debug(
				"Configured token key cache with cacheDuration={} seconds, cacheSize={} and statisticsRecording={}",
				getCacheConfiguration().getCacheDuration().getSeconds(), getCacheConfiguration().getCacheSize(),
				getCacheConfiguration().isCacheStatisticsEnabled());
		return this;
	}

	/**
	 * Overwrites the service to be used to request the Json web keys.
	 *
	 * @param tokenKeyService
	 *            the service to request the json web key set.
	 * @return this
	 */
	public OAuth2TokenKeyServiceWithCache withTokenKeyService(OAuth2TokenKeyService tokenKeyService) {
		this.tokenKeyService = tokenKeyService;
		return this;
	}

	/**
	 * Returns the cached key by id and type or requests the keys from the jwks URI
	 * of the identity service.
	 *
	 * @param keyAlgorithm
	 *            the Key Algorithm of the Access Token.
	 * @param keyId
	 *            the Key Id of the Access Token.
	 * @param keyUri
	 *            the Token Key Uri (jwks) of the Access Token (can be tenant
	 *            specific).
	 * @return a PublicKey
	 * @deprecated in favor of
	 *             {@link #getPublicKey(JwtSignatureAlgorithm, String, URI, String)}
	 */
	@Nullable
	@Deprecated
	public PublicKey getPublicKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI keyUri) {
		throw new UnsupportedOperationException("use getPublicKey(keyAlgorithm, keyId, keyUri, zoneId) instead");
	}

	/**
	 * Returns the cached key by id and type or requests the keys from the jwks URI
	 * of the identity service.
	 *
	 * @param keyAlgorithm
	 *            the Key Algorithm of the Access Token.
	 * @param keyId
	 *            the Key Id of the Access Token.
	 * @param keyUri
	 *            the Token Key Uri (jwks) of the Access Token (can be tenant
	 *            specific).
	 * @param zoneId
	 *            the Zone Id of the tenant
	 * @return a PublicKey
	 * @throws OAuth2ServiceException
	 *             in case the call to the jwks endpoint of the identity service
	 *             failed.
	 * @throws InvalidKeySpecException
	 *             in case the PublicKey generation for the json web key failed.
	 * @throws NoSuchAlgorithmException
	 *             in case the algorithm of the json web key is not supported.
	 *
	 */
	@Nullable
	public PublicKey getPublicKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI keyUri, String zoneId)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		assertNotNull(keyAlgorithm, "keyAlgorithm must not be null.");
		assertHasText(keyId, "keyId must not be null.");
		assertNotNull(keyUri, "keyUrl must not be null.");

		JsonWebKeySet keySet = getCache().getIfPresent(keyUri.toString());
		if (keySet == null || !keySet.containsZoneId(zoneId)) {
			keySet = retrieveTokenKeysAndUpdateCache(keyUri, zoneId, keySet); // creates and updates cache entries
		}
		if (!keySet.isZoneIdAccepted(zoneId)) {
			throw new OAuth2ServiceException("Invalid zone_uuid provided.");
		}
		for (JsonWebKey jwk : keySet.getAll()) {
			if (jwk.getId().equals(keyId) && jwk.getKeyAlgorithm().equals(keyAlgorithm)) {
				return jwk.getPublicKey();
			}
		}
		LOGGER.warn("No matching Key found in cache");
		return null;
	}

	private TokenKeyCacheConfiguration getCheckedConfiguration(CacheConfiguration cacheConfiguration) {
		Assertions.assertNotNull(cacheConfiguration, "CacheConfiguration must not be null!");
		int size = cacheConfiguration.getCacheSize();
		Duration duration = cacheConfiguration.getCacheDuration();
		if (size < 1000) {
			int currentSize = getCacheConfiguration().getCacheSize();
			LOGGER.error("Tried to set cache size to {} but the cache size must be 1000 or more."
					+ " Cache size will remain at: {}", size, currentSize);
			size = currentSize;
		}
		if (duration.getSeconds() < 600) {
			Duration currentDuration = getCacheConfiguration().getCacheDuration();
			LOGGER.error(
					"Tried to set cache duration to {} seconds but the cache duration must be at least 600 seconds."
							+ " Cache duration will remain at: {} seconds",
					duration.getSeconds(), currentDuration.getSeconds());
			duration = currentDuration;
		}
		if (duration.getSeconds() > 900) {
			Duration currentDuration = getCacheConfiguration().getCacheDuration();
			LOGGER.error(
					"Tried to set cache duration to {} seconds but the cache duration must be maximum 900 seconds."
							+ " Cache duration will remain at: {} seconds",
					duration.getSeconds(), currentDuration.getSeconds());
			duration = currentDuration;
		}
		return TokenKeyCacheConfiguration.getInstance(duration, size, cacheConfiguration.isCacheStatisticsEnabled());
	}

	private JsonWebKeySet retrieveTokenKeysAndUpdateCache(URI jwksUri, String zoneId,
			@Nullable JsonWebKeySet keySetCached)
			throws OAuth2ServiceException {
		String jwksJson;
		try {
			jwksJson = getTokenKeyService().retrieveTokenKeys(jwksUri, zoneId);
		} catch (OAuth2ServiceException e) {
			if (keySetCached != null) {
				keySetCached.withZoneId(zoneId, false);
			}
			throw e;
		}
		if (keySetCached != null) {
			return keySetCached.withZoneId(zoneId, true);
		}
		JsonWebKeySet keySet = JsonWebKeySetFactory.createFromJson(jwksJson).withZoneId(zoneId, true);
		getCache().put(jwksUri.toString(), keySet);
		return keySet;
	}

	private Cache<String, JsonWebKeySet> getCache() {
		if (cache == null) {
			Caffeine<Object, Object> cacheBuilder = Caffeine.newBuilder()
					.ticker(cacheTicker)
					.expireAfterWrite(getCacheConfiguration().getCacheDuration())
					.maximumSize(getCacheConfiguration().getCacheSize());
			if (getCacheConfiguration().isCacheStatisticsEnabled()) {
				cacheBuilder.recordStats();
			}
			cache = cacheBuilder.build();
		}
		return cache;
	}

	private OAuth2TokenKeyService getTokenKeyService() {
		if (tokenKeyService == null) {
			this.tokenKeyService = new DefaultOAuth2TokenKeyService();
		}
		return tokenKeyService;
	}

	@Nonnull
	@Override
	public CacheConfiguration getCacheConfiguration() {
		return cacheConfiguration;
	}

	@Override
	public void clearCache() {
		if (cache != null) {
			cache.invalidateAll();
		}
	}

	@Override
	public Object getCacheStatistics() {
		return getCacheConfiguration().isCacheStatisticsEnabled() ? getCache().stats() : null;
	}

}
