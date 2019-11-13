package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class TokenFilterTest {

	public static final Token TOKEN = Mockito.mock(Token.class);
	private TokenFilter cut = null;
	private HttpServletResponse httpResponse;
	private HttpServletRequest httpRequest;
	private FilterChain filterChain;

	@Before
	public void setUp() {
		httpRequest = Mockito.mock(HttpServletRequest.class);
		httpResponse = Mockito.mock(HttpServletResponse.class);
		filterChain = Mockito.mock(FilterChain.class);
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer fake token");
		cut = createComponent(ValidationResults.createValid());
	}

	@Test
	public void doFilter_noHeader_isUnauthorized() {
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);

		cut.doFilter(httpRequest, httpResponse, filterChain);

		assertThatResponseIsUnauthorized();
	}

	@Test
	public void doFilter_invalidToken_isUnauthorized() {
		cut = createComponent((ValidationResults.createInvalid("Token is not valid")));

		cut.doFilter(httpRequest, httpResponse, filterChain);

		assertThatResponseIsUnauthorized();
	}

	@Test
	public void doFilter_validToken_isNotUnauthorized() {
		cut = createComponent((ValidationResults.createValid()));

		cut.doFilter(httpRequest, httpResponse, filterChain);

		Mockito.verifyNoInteractions(httpResponse);
	}

	@Test
	public void doFilter_validToken_containedInSecurityContext() {
		cut = createComponent((ValidationResults.createValid()));

		cut.doFilter(httpRequest, httpResponse, filterChain);

		assertThat(SecurityContext.getToken()).isSameAs(TOKEN);
	}

	@Test
	public void doFilter_validToken_filterChainIsCalled() throws IOException, ServletException {
		cut = createComponent((ValidationResults.createValid()));

		cut.doFilter(httpRequest, httpResponse, filterChain);

		Mockito.verify(filterChain, times(1)).doFilter(httpRequest, httpResponse);
	}

	private TokenFilter createComponent(ValidationResult validationResult) {
		return new TokenFilter((header) -> TOKEN, (TOKEN) -> validationResult);
	}

	private void assertThatResponseIsUnauthorized() {
		Mockito.verify(httpResponse, times(1)).setStatus(HttpStatus.SC_UNAUTHORIZED);
		Mockito.verifyNoMoreInteractions(httpResponse);
	}

}