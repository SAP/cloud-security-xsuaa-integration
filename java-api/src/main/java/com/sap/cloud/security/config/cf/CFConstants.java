package com.sap.cloud.security.config.cf;

/**
 * Constants that simplifies access to service configuration properties in the
 * Cloud Foundry environment.
 */
public class CFConstants {
	public static final String VCAP_SERVICES = "VCAP_SERVICES";
	public static final String VCAP_APPLICATION = "VCAP_APPLICATION";
	public static final String CREDENTIALS = "credentials";
	public static final String SERVICE_PLAN = "plan";
	public static final String URL = "url";
	public static final String CLIENT_ID = "clientid";
	public static final String CLIENT_SECRET = "clientsecret";
	public static final String CERTIFICATE = "certificate";

	private CFConstants() {
	}

	/**
	 * Constants that are specific to the Xsuaa identity service.
	 */
	public static class XSUAA {
		private XSUAA() {
		}

		public static final String IDENTITY_ZONE = "identityzone";
		public static final String UAA_DOMAIN = "uaadomain";
		public static final String APP_ID = "xsappname";
		public static final String VERIFICATION_KEY = "verificationkey";
	}

	/**
	 * Constants that are specific to the Ias identity service.
	 */
	public static class IAS {
		private IAS() {
		}
	}

	/**
	 * Represents the service plans on CF marketplace. The various plans are
	 * considered in {@code CFEnvironment#loadXsuaa()}
	 */
	public enum Plan {
		DEFAULT, BROKER, APPLICATION, SPACE, APIACCESS, SYSTEM;

		public static Plan from(String planAsString) {
			return Plan.valueOf(planAsString.toUpperCase());
		}

	}
}
