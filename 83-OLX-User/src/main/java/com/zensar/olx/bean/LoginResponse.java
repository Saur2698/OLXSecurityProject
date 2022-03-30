package com.zensar.olx.bean;

public class LoginResponse {
	private String jwt;

	

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

	@Override
	public String toString() {
		return "LoginResponse [jwt=" + jwt + "]";
	}
	
	

}
