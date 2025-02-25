package app.security.apk;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/download/**").denyAll()
                        .requestMatchers("/*.apk").denyAll()
                        .anyRequest().permitAll()
                )
                .csrf(AbstractHttpConfigurer::disable); // 테스트 용

        return http.build();
    }
}
