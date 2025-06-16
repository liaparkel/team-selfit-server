package com.oopsw.selfit.config;

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
import org.springframework.web.filter.CorsFilter;

import com.google.gson.Gson;
import com.oopsw.selfit.auth.jwt.JwtAuthenticationFilter;
import com.oopsw.selfit.auth.jwt.JwtBasicAuthenticationFilter;
import com.oopsw.selfit.auth.jwt.JwtProperties;
import com.oopsw.selfit.auth.jwt.JwtTokenManager;
import com.oopsw.selfit.auth.service.CustomOAuth2UserService;
import com.oopsw.selfit.auth.service.CustomUserDetailsService;
import com.oopsw.selfit.repository.MemberRepository;

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

		http.addFilter(corsFilter);
		http.addFilter(new JwtAuthenticationFilter(authenticationManager, customOAuth2UserService));
		http.addFilter(new JwtBasicAuthenticationFilter(authenticationManager, memberRepository, customOAuth2UserService, customUserDetailsService));

		http
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfo -> userInfo
					.userService(customOAuth2UserService))
				.successHandler(oAuth2SuccessHandler())
				.failureHandler(oAuth2FailureHandler())
			);

		return http.build();

	}

	@Bean
	public AuthenticationSuccessHandler oAuth2SuccessHandler() {
		return (request, response, authentication) -> {
			String jwtToken = JwtTokenManager.createJwtToken(authentication);
			response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);

			String html = """
        <!DOCTYPE html>
        <html lang="ko">
        <head><meta charset="UTF-8"><title>로그인 처리중</title></head>
        <body>
        <script>
          const token = "%s%s";
          if (window.opener) {
            window.opener.postMessage({ token: token }, "http://127.0.0.1:8880");
          }
          setTimeout(() => window.close(), 100);
        </script>
        <p>로그인 처리 중입니다...</p>
        </body>
        </html>
        """.formatted(JwtProperties.TOKEN_PREFIX, jwtToken);

			response.setContentType("text/html;charset=UTF-8");
			response.getWriter().write(html);

		};
	}

	@Bean
	public AuthenticationFailureHandler oAuth2FailureHandler() {
		return (request, response, exception) -> {
			String email = (String)request.getAttribute("email");
			String name = (String)request.getAttribute("name");
			String redirectUrl = "http://127.0.0.1:8880/html/account/signup-oauth.html";
			
			String html = """
            <!DOCTYPE html>
            <html lang="ko">
            <head><meta charset="UTF-8"><title>회원가입</title></head>
            <body>
            <script>
                if (window.opener) {
                    window.opener.postMessage({ redirect: "%s", email: "%s", name: "%s" }, "http://127.0.0.1:8880");
                }
                setTimeout(() => window.close(), 100);
            </script>
            <p> 처리 중입니다...</p>
            </body>
            </html>
            """.formatted(redirectUrl, email, name);

			response.setContentType("text/html;charset=UTF-8");
			response.getWriter().write(html);
		};
	}

}