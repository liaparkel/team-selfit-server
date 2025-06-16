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
import jakarta.servlet.http.HttpSession;
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
				.requestMatchers(HttpMethod.GET,
					"/api/board/list",
					"/api/board/*",
					"/api/board/comments")
				.permitAll()
				.requestMatchers(HttpMethod.POST, "/api/account/member").permitAll()
				.requestMatchers("/api/account/member/check-login").permitAll()
				.requestMatchers("/api/board/**").hasRole("USER")
				.requestMatchers("/api/dashboard/**").hasRole("USER")
				.requestMatchers("/api/account/member/**").hasRole("USER")
				.anyRequest().permitAll()
			);

		// http.formLogin(form -> form
		// 	.loginPage("/account/login")
		// 	.loginProcessingUrl("/api/account/login-process")
		// 	.usernameParameter("loginId")
		// 	.passwordParameter("loginPassword")
		// 	.defaultSuccessUrl("/dashboard")
		// 	.successHandler(successHandler())
		// 	.failureHandler(failureHandler())
		// 	.permitAll()
		// );

		//always: 항상 새로 생성 if_required: 인증시에만 생성, never: 새로생성안하지만 기존거는 유지
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		//form 로그인 차단
		http.formLogin(form -> form.disable());

		//http 기본설정 무시
		http.httpBasic(httpBasic -> httpBasic.disable());

		http.addFilter(corsFilter);
		http.addFilter(new JwtAuthenticationFilter(authenticationManager));
		http.addFilter(
			new JwtBasicAuthenticationFilter(authenticationManager, memberRepository, customOAuth2UserService,
				customUserDetailsService));

		http
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfo -> userInfo
					.userService(customOAuth2UserService))
				.successHandler(oAuth2SuccessHandler())
				.failureHandler(oAuth2FailureHandler())
			);

		// http.logout(logout -> logout
		// 	.logoutUrl("/account/logout")
		// 	.logoutSuccessUrl("/account/login")
		// 	.invalidateHttpSession(true)
		// 	.clearAuthentication(true)
		// 	.deleteCookies("JSESSIONID")
		// );

		return http.build();

	}

	@Bean
	public AuthenticationSuccessHandler successHandler() {
		return (request, response, authentication) -> {
			response.setStatus(HttpServletResponse.SC_OK);
			response.setContentType("application/json;charset=UTF-8");

			Map<String, Object> result = new HashMap<>();
			result.put("message", "로그인 성공");
			result.put("status", 200);

			gson.toJson(result, response.getWriter());
		};
	}

	@Bean
	public AuthenticationFailureHandler failureHandler() {
		return (request, response, exception) -> {
			String loginId = request.getParameter("loginId"); // 사용자가 입력한 로그인 ID

			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.setContentType("application/json;charset=UTF-8");

			Map<String, Object> error = new HashMap<>();
			error.put("message", "아이디 또는 비밀번호가 올바르지 않습니다.");
			error.put("status", 401);
			gson.toJson(error, response.getWriter());
		};
	}

	// OAuth2 로그인용 성공 핸들러 추가
	@Bean
	public AuthenticationSuccessHandler oAuth2SuccessHandler() {
		return (request, response, authentication) -> {
			SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);

			if (savedRequest != null) {
				String targetUrl = savedRequest.getRedirectUrl();
				if (!targetUrl.contains("/api/")) {
					response.sendRedirect(targetUrl);
					return;
				}
			}

			// 저장된 요청이 없거나 API 요청인 경우 대시보드로
			response.sendRedirect("/dashboard");
		};
	}

	@Bean
	public AuthenticationFailureHandler oAuth2FailureHandler() {
		return (request, response, exception) -> {
			HttpSession session = request.getSession(false);
			String email = (String)session.getAttribute("email");
			String name = (String)session.getAttribute("name");

			response.sendRedirect("/account/signup-oauth");
		};
	}

}