package com.sap.cloud.security.x509;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

/**
 * Interface for accessing X509 certificates.
 */
public interface X509CertSelector {

	String getCertificate(HttpServletRequest request);

	@Nullable
	static X509CertSelector create() {
		if (Environments.getCurrent().getType() == Environment.Type.CF) {
			return new CFx509CertSelector();
		} else
			return null;
	}
}
