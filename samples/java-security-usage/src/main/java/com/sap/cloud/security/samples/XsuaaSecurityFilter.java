package com.sap.cloud.security.samples;

import com.sap.cloud.security.servlet.TokenAuthenticationResult;
import com.sap.cloud.security.servlet.XsuaaTokenAuthenticator;
import com.sap.cloud.security.token.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

import static com.sap.cloud.security.token.TokenClaims.*;

@WebFilter("/*") // filter for any endpoint
public class XsuaaSecurityFilter implements Filter {
	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaSecurityFilter.class);
	private final XsuaaTokenAuthenticator xsuaaTokenAuthenticator;

	public XsuaaSecurityFilter() {
		xsuaaTokenAuthenticator = new XsuaaTokenAuthenticator();
	}

	@Override
	public void init(FilterConfig filterConfig) {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		try {
			TokenAuthenticationResult authenticationResult = xsuaaTokenAuthenticator.validateRequest(request, response);
			if (authenticationResult.isAuthenticated()) {
				LOGGER.debug("AUTHENTICATED");
				chain.doFilter(request, response);
			} else {
				LOGGER.debug("UNAUTHENTICATED");
				sendUnauthenticatedResponse(response, authenticationResult.getUnauthenticatedReason());
			}
		} finally {
			SecurityContext.clear();
		}
	}

	private void sendUnauthenticatedResponse(ServletResponse response, String unauthenticatedReason)  {
		if (response instanceof HttpServletResponse) {
			try {
				HttpServletResponse httpServletResponse = (HttpServletResponse) response;
				httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, unauthenticatedReason); // 401
			} catch (IOException e) {
				LOGGER.error("Failed to send error response", e);
			}
		}
	}

	public static void sendUnauthorizedResponse(ServletResponse response, String missingScope)  {
		if (response instanceof HttpServletResponse) {
			try {
				String user = Objects.nonNull(SecurityContext.getAccessToken()) ? SecurityContext.getToken().getClaimAsString(USER_NAME) : "<Unknown>";
				HttpServletResponse httpServletResponse = (HttpServletResponse) response;
				LOGGER.error("User {} is unauthorized. User does not have scope {}.", user, missingScope);
				httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "User " + user + " is unauthorized."); // 403
			} catch (IOException e) {
				LOGGER.error("Failed to send error response", e);
			}
		}
	}

	@Override
	public void destroy() {
	}
}
