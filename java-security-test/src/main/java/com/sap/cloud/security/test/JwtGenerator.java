package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.token.validation.validators.JwtSignatureAlgorithm;
import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.sap.cloud.security.token.TokenHeader.*;

/**
 * Jwt {@link Token} builder class to generate tokes for testing purposes.
 */
public class JwtGenerator {
	public static final Instant NO_EXPIRE_DATE = new GregorianCalendar(2190, 11, 31).getTime().toInstant();
	public static final String DEFAULT_KEY_ID = "default-kid";
	public static final String DEFAULT_KEY_ID_IAS = "default-kid-ias";
	public static final String DEFAULT_ZONE_ID = "the-zone-id";
	public static final String DEFAULT_USER_ID = "the-user-id";

	private static final Logger LOGGER = LoggerFactory.getLogger(JwtGenerator.class);
	private static final String DEFAULT_JWKS_URL = "http://localhost/token_keys";
	private static final char DOT = '.';

	private final JSONObject jsonHeader = new JSONObject();
	private final JSONObject jsonPayload = new JSONObject();

	private SignatureCalculator signatureCalculator;
	private Service service;

	private JwtSignatureAlgorithm signatureAlgorithm;
	private PrivateKey privateKey = RSAKeys.generate().getPrivate();
	private String appId; // this is specific to XSUAA service
	private List<String> scopes = new ArrayList<>();
	private List<String> localScopes = new ArrayList<>();

	private JwtGenerator(Service service, SignatureCalculator signatureCalculator) {
		this.service = service;
		this.signatureCalculator = signatureCalculator;
		predefineTokenClaims();
	}

	/**
	 * This factory method creates an {@link JwtGenerator} instance that can be used
	 * to create tokens for testing purposes. The tokens are prefilled with data so
	 * that they can be validated successfully.
	 *
	 * @param service
	 *            the {@link Service} for which the token should be generated
	 * @param clientId
	 *            the authorization party of the token.
	 * @return a new {@link JwtGenerator} instance.
	 */
	public static JwtGenerator getInstance(Service service, String clientId) {
		JwtGenerator instance = new JwtGenerator(service, JwtGenerator::calculateSignature);
		instance.setDefaultsForNewToken(clientId);
		return instance;
	}

	/**
	 * This factory method creates an {@link JwtGenerator} instance that is
	 * prefilled with data provided by the file resource found at
	 * {@code tokenJsonResource}. This resource file contains data for the token
	 * payload and header. The file is expected to be in the following JSON format:
	 *
	 * <pre>
	 * 	"header": {
	 * 		"alg": "RS256",
	 * 		"kid": "kid-custom"
	 *        },
	 * 	"payload": {
	 * 		"zid" : "zone-id",
	 * 		"scope": [
	 * 			"openid",
	 * 			"app1.scope"
	 * 		]
	 *    }
	 * </pre>
	 *
	 * The payload and header data from the file will be written into the token
	 * being generated. Note that some properties are overridden. This is for
	 * convenience so that the token can be verified in a test setup rather then its
	 * original production setup. The following header and payload properties are
	 * overridden:
	 * <ul>
	 * <li>Header: jku, kid</li>
	 * <li>Payload: exp, iss</li>
	 * </ul>
	 *
	 * If you want to override those fields you need to do so manually with the
	 * respective methods from the {@link JwtGenerator} instance.
	 *
	 * @param tokenJsonResource
	 *            the resource path to the file containing the json file, e.g.
	 *            "/token.json"
	 * @return a new {@link JwtGenerator} instance.
	 * @throws JsonParsingException
	 *             if the file does not contain a valid json object
	 * @throws IllegalArgumentException
	 *             if the given file cannot be read
	 */
	public static JwtGenerator getInstanceFromFile(Service service, String tokenJsonResource) {
		return new JwtGenerator(service, JwtGenerator::calculateSignature).fromFile(tokenJsonResource);
	}

	// used for testing
	static JwtGenerator getInstance(Service service, SignatureCalculator signatureCalculator) {
		JwtGenerator instance = new JwtGenerator(service, signatureCalculator);
		instance.setDefaultsForNewToken("client-id-not-relevant-here");
		return instance;
	}

	private JwtGenerator fromFile(String tokenJsonResource) {
		String tokenJson = read(tokenJsonResource);
		JSONObject jsonObject = createJsonObject(tokenJson);
		JSONObject header = jsonObject.optJSONObject("header");
		JSONObject payload = jsonObject.optJSONObject("payload");
		copyJsonProperties(filterPayload(payload), jsonPayload);
		copyJsonProperties(filterHeader(header), jsonHeader);
		this.signatureAlgorithm = extractAlgorithm(jsonHeader).orElse(JwtSignatureAlgorithm.RS256);
		return this;
	}

	private void setDefaultsForNewToken(String azp) {
		this.signatureAlgorithm = JwtSignatureAlgorithm.RS256;
		withHeaderParameter(ALGORITHM, JwtSignatureAlgorithm.RS256.value());
		withClaimValue(TokenClaims.AUTHORIZATION_PARTY, azp);
		withClaimValue(TokenClaims.XSUAA.CLIENT_ID, azp); // Client Id left for backward compatibility
		if (service == Service.IAS) {
			jsonPayload.put(TokenClaims.AUDIENCE, azp);
			jsonPayload.put(TokenClaims.SAP_GLOBAL_ZONE_ID, DEFAULT_ZONE_ID);
			jsonPayload.put(TokenClaims.SAP_GLOBAL_USER_ID, DEFAULT_USER_ID);
		} else {
			withClaimValue(TokenClaims.XSUAA.CLIENT_ID, azp); // Client Id left for backward compatibility
			jsonPayload.put(TokenClaims.AUDIENCE, Arrays.asList(azp));
			jsonPayload.put(TokenClaims.XSUAA.ZONE_ID, DEFAULT_ZONE_ID);
			jsonPayload.put(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE, createJsonObject("{\"enhancer\" : \"XSUAA\"} "));
		}
	}

	private void predefineTokenClaims() {
		withExpiration(NO_EXPIRE_DATE);
		if (service == Service.IAS) {
			withHeaderParameter(KEY_ID, DEFAULT_KEY_ID_IAS);
		}
		if (service == Service.XSUAA) {
			withHeaderParameter(KEY_ID, DEFAULT_KEY_ID);
			withHeaderParameter(JWKS_URL, DEFAULT_JWKS_URL);
		}
	}

	/**
	 * Sets the header parameter with the given name to the given string value.
	 *
	 * @param parameterName
	 *            the name of the header parameter to be set.
	 * @param value
	 *            the string value of the header parameter to be set.
	 * @return the builder object.
	 */
	public JwtGenerator withHeaderParameter(String parameterName, String value) {
		jsonHeader.put(parameterName, value);
		return this;
	}

	/**
	 * Sets the claim with the given name to the given string value. Note: for
	 * overwriting client Id claim, "azp" claim value should be overwritten instead
	 * of deprecated "cid"
	 *
	 * @param claimName
	 *            the name of the claim to be set.
	 * @param value
	 *            the string value of the claim to be set.
	 * @return the builder object.
	 */
	public JwtGenerator withClaimValue(String claimName, String value) {
		jsonPayload.put(claimName, value);
		return this;
	}

	/**
	 * Sets the claim with the given name to the given string value. Note: for
	 * overwriting client Id claim, "azp" claim value should be overwritten instead
	 * of deprecated "cid"
	 *
	 * @param claimName
	 *            the name of the claim to be set.
	 * @param object
	 *            the string value of the claim to be set.
	 * @return the builder object.
	 * @throws JsonParsingException
	 *             if the given object does not contain valid json.
	 */
	public JwtGenerator withClaimValue(String claimName, JsonObject object) {
		try {
			jsonPayload.put(claimName, new JSONObject(object.asJsonString()));
		} catch (JSONException e) {
			throw new JsonParsingException(e.getMessage());
		}
		return this;
	}

	/**
	 * Sets the claims with the given names to the given string value. Note: for
	 * overwriting client Id claim, "azp" claim value should be overwritten instead
	 * of deprecated "cid"
	 *
	 * @param claimName
	 *            the name of the claim to be set.
	 * @param map
	 *            map of key value pairs of claims to be set.
	 * @return the builder object.
	 * @throws JsonParsingException
	 *             if the given object does not contain valid json.
	 */
	public JwtGenerator withClaimValue(String claimName, Map<String, String> map) {
		try {
			jsonPayload.put(claimName, map);
		} catch (JSONException e) {
			throw new JsonParsingException(e.getMessage());
		}
		return this;
	}

	/**
	 * Sets the claim with the given name to the given string values. Note: for
	 * overwriting client Id claim, "azp" claim value should be overwritten instead
	 * of deprecated "cid"
	 *
	 * @param claimName
	 *            the name of the claim to be set.
	 * @param values
	 *            the string values of the claims to be set.
	 * @return the builder object.
	 */
	public JwtGenerator withClaimValues(String claimName, String... values) {
		jsonPayload.put(claimName, values);
		return this;
	}

	/**
	 * This method will fill the token with all the claims that are defined inside
	 * the given file. The file must contain a valid json object. Note: for
	 * overwriting client Id claim, "azp" claim value should be overwritten instead
	 * of deprecated "cid"
	 *
	 * @throws JsonParsingException
	 *             if the file does not contain a valid json object.
	 * @throws IOException
	 *             when the file cannot be read or does not exist.
	 * @param claimsJsonResource
	 *            the resource path to the file containing the claims in json
	 *            format, e.g. "/claims.json"
	 * @return the builder object.
	 */
	public JwtGenerator withClaimsFromFile(String claimsJsonResource) throws IOException {
		String claimsJson = read(claimsJsonResource);
		JSONObject jsonObject = createJsonObject(claimsJson);
		copyJsonProperties(jsonObject, jsonPayload);
		return this;
	}

	/**
	 * Sets the expiration claim (exp) of the token to the given moment in time.
	 *
	 * @param expiration
	 *            the moment in time when the token will be expired.
	 * @return the builder object.
	 */
	public JwtGenerator withExpiration(@Nonnull Instant expiration) {
		jsonPayload.put(TokenClaims.EXPIRATION, expiration.getEpochSecond());
		return this;
	}

	/**
	 * Sets the signature algorithm that is used to create the signature of the
	 * token.
	 *
	 * @param signatureAlgorithm
	 *            the signature algorithm.
	 * @return the builder object.
	 */
	public JwtGenerator withSignatureAlgorithm(JwtSignatureAlgorithm signatureAlgorithm) {
		if (signatureAlgorithm != JwtSignatureAlgorithm.RS256) {
			throw new UnsupportedOperationException(signatureAlgorithm + " is not supported yet");
		}
		this.signatureAlgorithm = signatureAlgorithm;
		return this;
	}

	/**
	 * Sets the private key that is used to sign the token.
	 *
	 * @param privateKey
	 *            the private key.
	 * @return the builder object.
	 */
	public JwtGenerator withPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
		return this;
	}

	/**
	 * Sets the roles as claim "scope" to the jwt. Consecutive calls of this method
	 * will overwrite the data that has previously been set. Calls of this method
	 * however do not overwrite the data set via
	 * {@link #withLocalScopes(String...)}}. Note that this is specific to tokens of
	 * service type {@link Service#XSUAA}.
	 *
	 * @param scopes
	 *            the scopes that should be part of the token
	 * @return the JwtGenerator itself
	 * @throws IllegalArgumentException
	 *             if service is not {@link Service#XSUAA}
	 */
	public JwtGenerator withScopes(String... scopes) {
		if (service == Service.XSUAA) {
			this.scopes = Arrays.asList(scopes);
			putScopesInJsonPayload();
		} else {
			throw new UnsupportedOperationException("Scopes are not supported for service " + service);
		}
		return this;
	}

	/**
	 * Works like {@link #withScopes(String...)}} but prefixes the scopes with
	 * "appId.". For example if the appId is "xsapp", the scope "Read" will be
	 * converted to "xsapp.Read". Make sure the appId has been set via
	 * {@link #withAppId(String)} before calling this method. Consecutive calls of
	 * this method will overwrite the data that has previously been set. Calls of
	 * this method however do not overwrite the data set via
	 * {@link #withScopes(String...)}}. Note that this is specific to tokens of
	 * service type {@link Service#XSUAA}.
	 *
	 *
	 * @param scopes
	 * @return the JwtGenerator itself
	 * @throws IllegalStateException
	 *             if the appId has not been set via {@link #withAppId(String)}
	 */
	public JwtGenerator withLocalScopes(String... scopes) {
		if (appId == null) {
			throw new IllegalStateException("Cannot create local scopes because appId has not been set!");
		}
		if (service == Service.XSUAA) {
			localScopes = Stream.of(scopes)
					.map(scope -> appId + "." + scope)
					.collect(Collectors.toList());
			putScopesInJsonPayload();
		} else {
			throw new UnsupportedOperationException("Scopes are not supported for service " + service);
		}
		return this;
	}

	/**
	 * This method does not actually set data on the token itself but sets the appId
	 * that is used by {@link #withLocalScopes(String...)} to create the local
	 * scopes.
	 *
	 * @param appId
	 *            the appId to be used for local scopes creation
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator withAppId(String appId) {
		this.appId = appId;
		return this;
	}

	/**
	 * Builds and signs the token using the the algorithm set via
	 * {@link #withSignatureAlgorithm(JwtSignatureAlgorithm)} and the given key. By
	 * default{@link JwtSignatureAlgorithm#RS256} is used.
	 *
	 * @return the token.
	 */
	public Token createToken() {
		if (privateKey == null) {
			throw new IllegalStateException("Private key was not set!");
		}
		switch (service) {
		case IAS:
			return new SapIdToken(createTokenAsString());
		case XSUAA:
			return new XsuaaToken(createTokenAsString());
		default:
			throw new UnsupportedOperationException("Identity Service " + service + " is not supported.");
		}
	}

	private JSONObject filterPayload(JSONObject payload) {
		if (payload != null) {
			payload.remove(TokenClaims.EXPIRATION);
			payload.remove(TokenClaims.ISSUER);
		}
		return payload;
	}

	private JSONObject filterHeader(JSONObject header) {
		if (header != null) {
			header.remove(TokenHeader.JWKS_URL);
			header.remove(TokenHeader.KEY_ID);
		}
		return header;
	}

	private void copyJsonProperties(JSONObject source, JSONObject target) {
		if (source != null) {
			for (String key : source.keySet()) {
				Object value = source.get(key);
				target.put(key, value);
			}
		}
	}

	private JSONObject createJsonObject(String claimsJson) {
		try {
			return new JSONObject(claimsJson);
		} catch (JSONException e) {
			throw new JsonParsingException(e.getMessage());
		}
	}

	private void putScopesInJsonPayload() {
		List<String> resultingScopes = Stream.concat(localScopes.stream(), scopes.stream())
				.collect(Collectors.toList());
		jsonPayload.put(TokenClaims.XSUAA.SCOPES, resultingScopes);
	}

	private String createTokenAsString() {
		String header = base64Encode(jsonHeader.toString().getBytes());
		String payload = base64Encode(jsonPayload.toString().getBytes());
		String headerAndPayload = header + DOT + payload;
		String signature = calculateSignature(headerAndPayload);
		return headerAndPayload + DOT + signature;
	}

	private static byte[] calculateSignature(PrivateKey privateKey, JwtSignatureAlgorithm signatureAlgorithm,
			byte[] dataToSign) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		Signature signature = Signature.getInstance(signatureAlgorithm.javaSignature());
		signature.initSign(privateKey);
		signature.update(dataToSign);
		return signature.sign();
	}

	private String calculateSignature(String headerAndPayload) {
		try {
			return base64Encode(signatureCalculator
					.calculateSignature(privateKey, signatureAlgorithm, headerAndPayload.getBytes()));
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Algorithm '{}' not found.", signatureAlgorithm.javaSignature());
			throw new UnsupportedOperationException(e);
		} catch (SignatureException e) {
			LOGGER.error("Error creating JWT signature.");
			throw new UnsupportedOperationException(e);
		} catch (InvalidKeyException e) {
			LOGGER.error("Invalid private key.");
			throw new UnsupportedOperationException(e);
		}
	}

	private String base64Encode(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	interface SignatureCalculator {
		byte[] calculateSignature(PrivateKey privateKey, JwtSignatureAlgorithm algorithm, byte[] dataToSign)
				throws InvalidKeyException, SignatureException, NoSuchAlgorithmException;
	}

	private String read(String tokenJsonResource) {
		try {
			return IOUtils.resourceToString(tokenJsonResource, StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new IllegalArgumentException("Error reading resource file: " + e.getMessage());
		}
	}

	private Optional<JwtSignatureAlgorithm> extractAlgorithm(JSONObject jsonHeader) {
		if (jsonHeader == null || !jsonHeader.has(ALGORITHM)) {
			return Optional.empty();
		}
		String alg = jsonHeader.getString(ALGORITHM);
		JwtSignatureAlgorithm algorithm = JwtSignatureAlgorithm.fromValue(alg);
		if (algorithm == null) {
			throw new UnsupportedOperationException(String.format("Algorithm %s of token not supported!", alg));
		}
		return Optional.of(algorithm);
	}

}
