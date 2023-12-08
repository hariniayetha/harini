package com.example.Basic.Demo.Entity.config;

import com.example.Security.User.Demo.repo.AppUserRepo;
import com.example.Security.User.Demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
//import org.springframework.web.cors.CorsConfiguration;
//import java.util.Arrays;
//import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

    @Autowired
    private JwtTokenUtils jwtTokenUtils;

    @Autowired
    private AppUserRepo appUserRepo;

    @Autowired
    private UserService userService;


    private String[] PUBLIC_RESOURCE_AND_URL = {"/",
            "/api/v1/app/user/sign-up",
            "/api/v1/app/user/sign-in"
    };

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        // We don't need CSRF for this example
//
//        http.cors().configurationSource(request -> {
//            String[] methods = { "POST"};
//            System.out.println("Enter 1");
//            CorsConfiguration config = new CorsConfiguration();
//            config.setAllowedHeaders(Collections.singletonList("*"));
//            config.setAllowedMethods(Arrays.asList(methods));
//            config.addAllowedOriginPattern("1.1.1.1");
//            config.setAllowCredentials(true);
//            return config;
//        });

//        try {
//            http.csrf().disable();
//            http.authorizeHttpRequests()
//                    .requestMatchers("/api/v1/app/user/*").permitAll()
//                    .and()
//                    .addFilterBefore(
//                            new CustomAuthFilter(userService), BasicAuthenticationFilter.class).
//                    addFilterBefore(new CustomCORSFilter(), ChannelProcessingFilter.class);
//            return http.build();
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }

        //for jwtAuthenticationFIlter
        http.csrf()
                .disable()
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and()
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler()).and().addFilterBefore(
                        new JwtAuthenticationFilter(jwtTokenUtils, appUserRepo), BasicAuthenticationFilter.class).
                addFilterBefore(new CustomCORSFilter(), ChannelProcessingFilter.class);
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(true)
                .ignoring()
                .requestMatchers(PUBLIC_RESOURCE_AND_URL);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

}
