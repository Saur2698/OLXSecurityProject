package com.zensar.olx.rest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.zensar.olx.bean.LoginResponse;
import com.zensar.olx.bean.LoginUser;
import com.zensar.olx.bean.OlxUser;
import com.zensar.olx.db.TokenStorage;
import com.zensar.olx.service.OlxUserService;
import com.zensar.olx.util.JwtUtil;

@RestController
public class OlxUserController {

	@Autowired
	OlxUserService service;

	@Autowired
	private AuthenticationManager manager;

	@Autowired
	private JwtUtil util;

	/**
	 * This is the rest specification for authenticating token for user details
	 * 
	 * @param user
	 * @return
	 */
	@PostMapping("/user/authenticate")
	public LoginResponse login(@RequestBody LoginUser user) 
	{
		UsernamePasswordAuthenticationToken authenticationToken;
		authenticationToken = new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
		
		try {
			manager.authenticate(authenticationToken);// authenticate user

			// User is authenticated successfully then generate the token and retuen it back
			
			String token = util.generateToken(user.getUserName());
			
			TokenStorage.storeToken(token, token);
			
			LoginResponse loginResponse = new LoginResponse();
			loginResponse.setJwt(token);
			System.out.println(loginResponse);
			return loginResponse;
		} 
		catch (Exception e) {
			// Authentication is failed

			e.printStackTrace();
			throw e;
		}
	}

	@PostMapping("/user")
	public OlxUser addOlxUser(@RequestBody OlxUser olxUser) {
		return this.service.addOlxUser(olxUser);
	}

	@GetMapping("/user/{uid}")
	public OlxUser findOlxUserById(@PathVariable(name = "uid") int id) {
		return this.service.findOlxUser(id);
	}

	@GetMapping("/user/find/{userName}")
	public OlxUser findOlxUserByName(@PathVariable(name = "userName") String name) {
		return this.service.findOlxUserByName(name);

	}

	@GetMapping("/token/validate")
	public ResponseEntity<Boolean> isValidateUser(@RequestHeader("Authorization") String authToken) {

		try {
			String validatedToken = util.validateToken(authToken.substring(7));
			return new ResponseEntity<Boolean>(true, HttpStatus.OK);
		} catch (Exception e) {

			e.printStackTrace();
			return new ResponseEntity<Boolean>(false, HttpStatus.BAD_REQUEST);
		}
	}

	@DeleteMapping("/user/logout")
	public ResponseEntity<Boolean> logout(@RequestHeader("Authorization") String authToken) {
		String token = authToken.substring(7);

		try {
			TokenStorage.removeToken(token);
			
			ResponseEntity<Boolean> responseEntity = new ResponseEntity<Boolean>(true, HttpStatus.OK);
			return responseEntity;
		} 
		    catch (Exception e)
		{
			ResponseEntity<Boolean> responseEntity = new ResponseEntity<Boolean>(false, HttpStatus.BAD_REQUEST);
			return responseEntity;
		}
	}

}
