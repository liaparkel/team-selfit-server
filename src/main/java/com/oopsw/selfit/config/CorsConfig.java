package com.oopsw.selfit.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true); //json 데이터 자바스크립트에서 해라
		config.addAllowedOriginPattern("*");
		config.addAllowedHeader("*"); //
		config.addAllowedMethod("*");
		config.setExposedHeaders(Arrays.asList("Access-Control-Allow-Headers", "selfitKosta"));
		source.registerCorsConfiguration("/**", config);

		return new CorsFilter(source);
	}

}
