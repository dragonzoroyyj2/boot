package com.example.demo.config;

import com.example.demo.filter.JwtAuthenticationFilter;
import com.example.demo.service.MyUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

    private final MyUserDetailsService myUserDetailsService;

    public SecurityConfig(MyUserDetailsService myUserDetailsService) {
        this.myUserDetailsService = myUserDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authz -> authz
                // ✅ 공개 API, 로그인, 정적 리소스, H2 콘솔 허용
            		
        		/*
        		 	직접 AntPathRequestMatcher 객체를 생성해서 전달하는 방식

					AntPathRequestMatcher 는 단순한 URL 패턴 매칭 전용 클래스
					(DispatcherServlet, MVC 여부와 무관하게 동작)
					
					주로 H2 콘솔, Actuator, 외부 서블릿 경로처럼 Spring MVC Controller 가 아닌 서블릿에도 적용할 때 
        		 	H2 콘솔은 org.h2.server.web.JakartaWebServlet 이라서 Spring MVC 컨트롤러가 아님

					따라서 "/h2-console/**" 를 그냥 문자열로 쓰면 Spring Security 6에서 충돌 ⚠️

					이럴 땐 AntPathRequestMatcher 로 명시해줘야 함
        		 */
                .requestMatchers(new AntPathRequestMatcher("/auth/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/api/public/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/login")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/css/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/js/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                
                //Spring MVC @Controller 나 @RestController 로 만든 /user/... 엔드포인트에 적용
                //Security 가 DispatcherServlet 경로를 잘 인식하기 때문에 별도 matcher 필요 없음
                //.requestMatchers("/admin/**").hasRole("ADMIN")      // ADMIN 권한 필요
                //.requestMatchers("/user/**").hasAnyRole("USER","ADMIN") // USER 또는 ADMIN
                
                // ✅ 그 외 모든 요청은 인증 필요
                .anyRequest().authenticated()
            )
            // ✅ 폼 로그인 (Thymeleaf 기반)
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/", true)
                .permitAll()
            )
            // ✅ 로그아웃
            .logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login?logout")
                .permitAll()
            )
            // ✅ API는 Stateless, 웹은 세션 유지 가능
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            );

        // ✅ H2 콘솔 iframe 허용
        http.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));

        // ✅ JWT 필터 등록 (API 요청 전용)
        http.addFilterBefore(
            new JwtAuthenticationFilter(myUserDetailsService),
            UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }

    // ✅ 비밀번호 암호화 (BCrypt)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ✅ DaoAuthenticationProvider (UserDetailsService + PasswordEncoder)
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(myUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // ✅ AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
