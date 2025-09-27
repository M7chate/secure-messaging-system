package mz.ujc.secure_messaging_system.config;

import mz.ujc.secure_messaging_system.entity.User;
import mz.ujc.secure_messaging_system.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Optional;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public UserDetailsService userDetailsService(UserService userService) {
        return username -> {
            Optional<User> userOpt = userService.findByUsername(username);
            if (userOpt.isEmpty()) {
                throw new UsernameNotFoundException("Usuário não encontrado: " + username);
            }
            User user = userOpt.get();
            return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities("USER")
                .build();
        };
    }
    
    @SuppressWarnings("removal")
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())  // CSRF desabilitado para APIs e WebSocket
            .headers(headers -> headers.frameOptions().disable()) // Para H2 console
            .authorizeHttpRequests(auth -> auth
                // Páginas públicas
                .requestMatchers("/", "/register", "/login", "/error", "/h2-console/**",
                                "/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                
                // WebSocket endpoints
                .requestMatchers("/ws/**", "/app/**", "/topic/**", "/queue/**").authenticated()
                
                // API endpoints públicos
                .requestMatchers("/api/public/**").permitAll()
                
                // Páginas autenticadas
                .requestMatchers("/dashboard", "/chat/**").authenticated()
                
                // API endpoints autenticados (incluindo upload/download)
                .requestMatchers("/api/upload/**", "/api/download/**", 
                               "/api/messages/**", "/api/chat/**", 
                               "/api/crypto/**").authenticated()
                
                // Qualquer outra requisição precisa de autenticação
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll()
            );
            
        return http.build();
    }
}
