package com.sap.cloud.security.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

/**
 * X509 certificate accessor implementation for Cloud Foundry environment.
 */
public class CFx509CertSelector implements X509CertSelector {

	private static final Logger LOGGER = LoggerFactory.getLogger(CFx509CertSelector.class);

	@Override
	@Nullable
	public String getCertificate(HttpServletRequest request) {

		LOGGER.debug("x-forwarded-client-cert: {}", request.getHeader("x-forwarded-client-cert"));
		return request.getHeader("x-forwarded-client-cert");
	}

}
