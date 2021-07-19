/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.Assertions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.Optional;

public class UriUtil {

	private static final Logger logger = LoggerFactory.getLogger(UriUtil.class);

	private UriUtil() {
		// use static methods
	}

	/**
	 * Utility method that replaces the subdomain of the URI with the given
	 * subdomain.
	 *
	 * @param uri
	 *            the URI to be replaced.
	 * @param subdomain
	 *            of the tenant.
	 * @return the URI with the replaced subdomain or the passed URI in case a
	 *         replacement was not possible.
	 */
	public static URI replaceSubdomain(@Nonnull URI uri, @Nullable String subdomain) {
		Assertions.assertNotNull(uri, "the uri parameter must not be null");
		if (hasText(subdomain) && hasSubdomain(uri)) {
			String newHost = subdomain + uri.getHost().substring(uri.getHost().indexOf('.'));
			try {
				return uri.resolve(new URI(uri.getScheme(), uri.getUserInfo(), newHost, uri.getPort(), uri.getPath(),
						uri.getQuery(), uri.getFragment()));
			} catch (URISyntaxException e) {
				logger.error("Could not replace subdomain {} in given uri {}", subdomain, uri);
				throw new IllegalArgumentException(e);
			}
		}
		logger.debug("the subdomain of the URI '{}' is not replaced by subdomain '{}'", uri, subdomain);
		return uri;
	}

	private static boolean hasSubdomain(URI uri) {
		return uri.getHost().contains(".");
	}

	private static boolean hasText(String string) {
		return Optional.ofNullable(string).filter(str -> !str.trim().isEmpty()).isPresent();
	}

	/**
	 * Utility method that expands the path of the URI.
	 *
	 * @param baseUri
	 *            the URI to be replaced.
	 * @param pathToAppend
	 *            the path to append.
	 * @return the URI with the path.
	 */
	// TODO rename to getUriWithPathAppended
	@Nonnull
	public static URI expandPath(URI baseUri, String pathToAppend) {
		try {
			String newPath = baseUri.getPath() + pathToAppend;
			if(Objects.nonNull(baseUri.getQuery()) || Objects.nonNull(baseUri.getFragment())) {
				logger.warn("As of version 2.8.0 queries {} and fragments {} are ignored.", baseUri.getQuery(), baseUri.getFragment());
			}
			return new URI(baseUri.getScheme(), baseUri.getUserInfo(), baseUri.getHost(), baseUri.getPort(),
					replaceDoubleSlashes(newPath), null, null);
		} catch (URISyntaxException e) {
			throw new IllegalStateException(e);
		}
	}

	@Nonnull
	private static String replaceDoubleSlashes(String newPath) {
		return newPath.replace("//", "/");
	}
}
