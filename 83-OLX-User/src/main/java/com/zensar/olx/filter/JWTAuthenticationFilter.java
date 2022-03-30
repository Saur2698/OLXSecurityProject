package com.zensar.olx.filter;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;

//Spring MVC, Rest internally uses servlet API
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.json.JsonParser;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.zensar.olx.db.TokenStorage;
import com.zensar.olx.util.JwtUtil;

//This is custom filter
//You need to add this filter in Spring filter chain 
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

	// Authorization is predefined header
	private String authorizationHeader = "Authorization";
	private final String BEARER = "Bearer";

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		JwtUtil jwtUtil = new JwtUtil();

		System.out.println("In doFilterInternal");
		// 1. Check if user has passed token , we do that by fetching value from
		// Authorization header
		String authorizationHeaderValue = request.getHeader(authorizationHeader);

		// if token is not passed Or if it does not start with Bearer
		// Don't do anything proceed to next filter in chain
		if (authorizationHeaderValue == null || !authorizationHeaderValue.startsWith(BEARER))

		{
			chain.doFilter(request, response); // invoke next security filter in chain
			return;
		}

		if (authorizationHeaderValue != null && authorizationHeaderValue.startsWith(BEARER)) {
			// Bearer is prefix to token value this is pre defined
			 // we want to remove "Bearer" from token value
			
			String token = authorizationHeaderValue.substring(7);

			if (token != null) {

				// Authorization Bearer token
				System.out.println(" authorizationHeaderValue-------> " + authorizationHeaderValue);
				System.out.println("Token Value------------------->" + token);

				// check if this token exists in Cache
				String jwttoken = authorizationHeaderValue.substring(7).trim();
				
				String tokenExists = TokenStorage.getToken(jwttoken);

				if (tokenExists == null) {
					chain.doFilter(request, response);
					return;
				}

				try {
					// validate the token
					String encodedPayload = jwtUtil.validateToken(token);
					// Token is valid
					String payload = new String(Base64.getDecoder().decode(encodedPayload));
					// from this payload we need to fetch username
					JsonParser jsonParser = JsonParserFactory.getJsonParser();
					Map<String, Object> parseMap = jsonParser.parseMap(payload);
					String username = (String) parseMap.get("username");

					// create UsernamePasswordAuthentication Token
					UsernamePasswordAuthenticationToken authenticationToken;
					authenticationToken = new UsernamePasswordAuthenticationToken(username, null,
							AuthorityUtils.createAuthorityList("ROLE_USER"));

					// Authenticate user
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);

				} catch (Exception e) {
					// if token is not valid
					e.printStackTrace();
				}

				// 2. if token not present ask user to login

				// 3. if token present fetch it and validates it.
			}
		}
		chain.doFilter(request, response);
	}
}
