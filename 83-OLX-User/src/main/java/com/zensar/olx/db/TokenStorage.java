package com.zensar.olx.db;

import java.util.HashMap;
import java.util.Map;

public class TokenStorage {
	
	private static Map<String, String> tokenCache;
	
	static
	{
		tokenCache = new HashMap<>();
	}
	//this method respnsibke for storing token in Cache on server
	//both token-kkey and token-value is token itself
	public static void storeToken(String key,String token)
	{
		tokenCache.put(key, token);
	}
	
	public static String removeToken(String key)
	{
		return tokenCache.remove(key);
	}
	
	public static String getToken(String key)
	{
		return tokenCache.get(key);
	}

}
