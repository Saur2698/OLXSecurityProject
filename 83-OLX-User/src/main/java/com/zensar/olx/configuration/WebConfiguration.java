package com.zensar.olx.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * *
 * @author SAURABH RAJ
 *This Configuration File is needed for Customizing CORS Configuration
 *CORS - Cross Origin Resource Sharing
 */

@Configuration
public class WebConfiguration implements WebMvcConfigurer {
	
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		
		registry
		         .addMapping("/**")
		         .allowedMethods("*")
		         .allowedOrigins("http://localhost:4200");
		
	}

}
