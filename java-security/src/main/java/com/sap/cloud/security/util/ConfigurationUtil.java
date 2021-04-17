package com.sap.cloud.security.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigurationUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationUtil.class);

	private ConfigurationUtil() {
	}

	/**
	 * Utility method that checks if provided property name is set as System
	 * Environment variable. If value is not set(null) or set to false it returns
	 * false. Any other value is interpreted as true.
	 *
	 * @param propertyName
	 *            name of System Environment variable
	 * @param defaultEnabled
	 *            is the default value of this property enabled? true if enabled :
	 *            false if disabled
	 * @return boolean value
	 */
	public static boolean isSysEnvPropertyEnabled(String propertyName, boolean defaultEnabled) {
		String isEnabled = System.getenv(propertyName);
		LOGGER.debug("System environment variable {} is set to {}", propertyName, isEnabled);
		if (defaultEnabled) {
			return isEnabled == null || !isEnabled.equalsIgnoreCase("false");
		} else {
			return isEnabled != null && !isEnabled.equalsIgnoreCase("false");
		}
	}
}
