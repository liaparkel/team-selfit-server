package com.oopsw.selfit.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.filter.CorsFilter;

import com.google.gson.Gson;
import com.oopsw.selfit.auth.jwt.JwtAuthenticationFilter;
import com.oopsw.selfit.auth.jwt.JwtBasicAuthenticationFilter;
import com.oopsw.selfit.auth.service.CustomOAuth2UserService;
import com.oopsw.selfit.auth.service.CustomUserDetailsService;
import com.oopsw.selfit.repository.MemberRepository;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final Gson gson = new Gson();
	private final CorsFilter corsFilter;
	private CustomOAuth2UserService customOAuth2UserService;
	private CustomUserDetailsService customUserDetailsService;

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws
		Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http, CustomOAuth2UserService customOAuth2UserService, AuthenticationManager authenticationManager,
		CorsFilter corsFilter, MemberRepository memberRepository,
		CustomUserDetailsService customUserDetailsService) throws
		Exception {
		http.csrf(csrf -> csrf.disable());
		http
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/api/board/list").permitAll()
				.requestMatchers("/api/board/detail/**").permitAll()
				.requestMatchers("/api/dashboard/food/openSearch").permitAll()
				.requestMatchers("/api/dashboard/exercise/openSearch").permitAll()
				.requestMatchers(HttpMethod.POST, "/api/account/member").permitAll()
				.requestMatchers("/api/account/member/check-login").permitAll()
				.requestMatchers("/api/board/**").hasRole("USER")
				.requestMatchers("/api/dashboard/**").hasRole("USER")
				.requestMatchers("/api/account/member/**").hasRole("USER")
				.anyRequest().permitAll()
			);

		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.formLogin(form -> form.disable());
		http.httpBasic(httpBasic -> httpBasic.disable());

		http
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfo -> userInfo
					.userService(customOAuth2UserService))
				.successHandler(oAuth2SuccessHandler())
				.failureHandler(oAuth2FailureHandler())
			);

		http.addFilter(corsFilter);
		http.addFilter(new JwtAuthenticationFilter(authenticationManager));
		http.addFilter(new JwtBasicAuthenticationFilter(authenticationManager, memberRepository, customOAuth2UserService, customUserDetailsService));

		return http.build();

	}

	@Bean
	public AuthenticationSuccessHandler oAuth2SuccessHandler() {
		return (request, response, authentication) -> {
			SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);

			response.setStatus(HttpServletResponse.SC_OK);
			if (savedRequest != null) {
				String targetUrl = savedRequest.getRedirectUrl();
				if (!targetUrl.contains("/api/")) {
					response.getWriter().println(Map.of("redirect_url", targetUrl));
				}
			}

			// 저장된 요청이 없거나 API 요청인 경우 대시보드로
			response.getWriter().println(Map.of("redirect_url", "/html/dashboard/dashboard.html"));
		};
	}

	@Bean
	public AuthenticationFailureHandler oAuth2FailureHandler() {
		return (request, response, exception) -> {

			Map<String, String> result = new HashMap<>(Map.of("message", "need signup"));

			String email = (String)request.getAttribute("email");
			String name = (String)request.getAttribute("name");
			result.put("email", email);
			result.put("name", name);

			response.sendRedirect("http://127.0.0.1:8880/html/account/signup-oauth.html");
			// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			// response.getWriter().println(result);
		};
	}

}