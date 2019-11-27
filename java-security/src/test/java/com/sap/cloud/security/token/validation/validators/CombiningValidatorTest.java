package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import org.junit.Test;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.util.Lists.newArrayList;

public class CombiningValidatorTest {

	private static final String FIRST_ERROR_MESSAGE = "firstMessage";
	private static final String SECOND_ERROR_MESSAGE = "secondMessage";

	@Test
	public void validate_containsNoValidators_validResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(new ArrayList<>());

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoValidValidators_validResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				newArrayList(validValidator(), validValidator()));

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_invalidResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				newArrayList(invalidValidator(), invalidValidator()));

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isErroneous()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_containsOnlyOneErrorMessages() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				newArrayList(validValidator(), invalidValidator(FIRST_ERROR_MESSAGE),
						invalidValidator(SECOND_ERROR_MESSAGE)));

		String error = combiningValidator.validate(null).getErrorDescription();

		assertThat(error).isEqualTo(FIRST_ERROR_MESSAGE);
	}

	private Validator<Token> validValidator() {
		return (obj) -> ValidationResults.createValid();
	}

	private Validator<Token> invalidValidator() {
		return invalidValidator(FIRST_ERROR_MESSAGE);
	}

	private Validator<Token> invalidValidator(String errorMessage) {
		return (obj) -> ValidationResults.createInvalid(errorMessage);
	}

}