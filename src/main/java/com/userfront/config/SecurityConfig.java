package com.userfront.config;

import java.security.SecureRandom;

//import org.hibernate.cfg.Environment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.userfront.service.UserServiceImpl.UserSecurityService;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)

public class SecurityConfig {

    @Autowired
    private Environment environment;

    @Autowired
    private UserSecurityService userSecurityService;

    private static final String SALT = "salt"; // Salt should be protected carefully

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12, new SecureRandom(SALT.getBytes()));
    }

    private static final String[] PUBLIC_MATCHERS = {
            "/webjars/**",
            "/css/**",
            "/js/**",
            "/images/**",
            "/",
            "/about/**",
            "/contact/**",
            "/error/**/*",
            "/console/**",
            "/signup"
    };

//    @Override
//    public void configure(HttpSecurity security) throws Exception {
//        // Enable CORS and disable CSRF
//        security = security.cors().and().csrf().disable();
//
//        // Set session management to stateless
//        security = security
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and();
//
//        // Set permissions on endpoints
//        security.authorizeRequests()
//                // Our public endpoints, secured endpoints and then open everything else that is static resource stuff
//                .antMatchers(HttpMethod.GET, "/api/config-props").permitAll()
//                .antMatchers(HttpMethod.GET, "/actuator/health").permitAll()
//                .antMatchers("/actuator**").authenticated()
//                .antMatchers("/api/**").authenticated()
//                .antMatchers(HttpMethod.GET, "/**").permitAll();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests((authz) -> authz
//                        .anyRequest().authenticated()
//                )
//                .httpBasic(withDefaults());

        http.authorizeRequests().antMatchers("/login").permitAll()

   //             .anyRequest().authenticated()
                .and().formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout().permitAll();


        return http.build();
            }
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/login");
    }



//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests().
////                antMatchers("/**").
//                antMatchers(PUBLIC_MATCHERS).
//                permitAll().anyRequest().authenticated();
//
//        http
//                .csrf().disable().cors().disable()
//                .formLogin().failureUrl("/index?error").defaultSuccessUrl("/userFront").loginPage("/index").permitAll()
//                .and()
//                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/index?logout").deleteCookies("remember-me").permitAll()
//                .and()
//                .rememberMe();
//    }

//
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    	 auth.inMemoryAuthentication().withUser("user").password("password").roles("USER"); //This is in-memory authentication
     //    auth.userDetailsService(userSecurityService).passwordEncoder(passwordEncoder());
    }
}


