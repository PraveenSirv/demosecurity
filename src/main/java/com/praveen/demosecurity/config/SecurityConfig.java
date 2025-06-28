package com.praveen.demosecurity.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

    //this method will provide custom security filter chain for the website
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(request -> request
                        .requestMatchers("register","login")
                        .permitAll()
                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }


//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails uesr1 = User
//                .withDefaultPasswordEncoder()
//                .username("vinit")
//                .password("1234")
//                .roles("USER")
//                .build();
//    "To use user created users"
//        UserDetails uesr2 = User
//                .withDefaultPasswordEncoder()
//                .username("manu")
//                .password("12345")
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(uesr1,uesr2);
//    }

}




//Absolutely! Here's a **line-by-line explanation** of your Spring Security configuration using JWT and custom filters:
//
//---
//
//```java
//@Configuration
//```
//
//* **Marks this class as a Spring configuration class** — used to define beans.
//* Equivalent to XML configuration (`<beans>`).
//
//---
//
//```java
//@EnableWebSecurity
//```
//
//* **Enables Spring Security** for the application.
//* Tells Spring to apply web security settings defined in this class.
//
//---
//
//```java
//public class SecurityConfig {
//```
//
//* The main configuration class for customizing Spring Security behavior.
//
//---
//
//```java
//@Autowired
//private UserDetailsService userDetailsService;
//```
//
//* Injects a custom `UserDetailsService` implementation.
//* Used to load user details (username, password, roles) from a database or in-memory store.
//
//---
//
//```java
//@Autowired
//private JwtFilter jwtFilter;
//```
//
//* Injects your custom JWT filter that will validate tokens before Spring handles the request.
//
//---
//
//### ✅ Security Filter Chain
//
//```java
//@Bean
//public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//```
//
//* Defines a custom security filter chain.
//* Spring uses this method to configure all security behavior (authentication, authorization, filters, etc.).
//
//---
//
//```java
//return httpSecurity
//```
//
//* Starts building the security configuration using fluent API.
//
//---
//
//```java
//.csrf(customizer -> customizer.disable())
//```
//
//* Disables CSRF protection.
//* Necessary for stateless APIs (e.g., when using JWT, not cookies).
//
//---
//
//```java
//.authorizeHttpRequests(request -> request
//        .requestMatchers("register","login")
//        .permitAll()
//```
//
//* Allows unauthenticated access to `/register` and `/login` endpoints.
//
//---
//
//```java
//.anyRequest().authenticated())
//```
//
//* All other endpoints **require authentication**.
//
//---
//
//```java
/// /.formLogin(Customizer.withDefaults())
//```
//
//* Commented out: if enabled, would allow form-based login.
//
//---
//
//```java
//.httpBasic(Customizer.withDefaults())
//```
//
//* Enables **HTTP Basic authentication** (username/password via headers).
//* Not ideal for production with JWT, but can be useful for testing or fallback.
//
//---
//
//```java
//.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//```
//
//* Makes the app **stateless** — it will not create or use HTTP sessions.
//* Essential when using JWT (no session memory).
//
//---
//
//```java
//.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
//```
//
//* Adds your custom `jwtFilter` **before** Spring's default `UsernamePasswordAuthenticationFilter`.
//* This ensures JWT validation happens early in the chain.
//
//---
//
//```java
//.build();
//```
//
//* Finalizes and returns the `SecurityFilterChain`.
//
//---
//
//### ✅ Authentication Provider
//
//```java
//@Bean
//public AuthenticationProvider authenticationProvider(){
//```
//
//* Defines a bean to handle authentication using your custom logic.
//
//---
//
//```java
//DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//```
//
//* Built-in authentication provider that uses `UserDetailsService`.
//
//---
//
//```java
//provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
//```
//
//* Uses **BCrypt hashing** to compare encrypted passwords.
//* `12` is the strength (number of hashing rounds). Higher = more secure but slower.
//
//---
//
//```java
//provider.setUserDetailsService(userDetailsService);
//return provider;
//```
//
//* Tells the provider to use your custom user details logic.
//
//---
//
//### ✅ Authentication Manager
//
//```java
//@Bean
//public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
//    return config.getAuthenticationManager();
//}
//```
//
//* Exposes the `AuthenticationManager` as a bean.
//* Used by Spring to handle authentication requests (e.g., login endpoint).
//
//---
//
//### ❌ Commented-Out In-Memory User Setup
//
//```java
////    @Bean
////    public UserDetailsService userDetailsService(){
//```
//
//* If uncommented, this would provide **hardcoded in-memory users**.
//
//---
//
//```java
////        UserDetails uesr1 = User
////                .withDefaultPasswordEncoder()
////                .username("vinit")
////                .password("1234")
////                .roles("USER")
////                .build();
//```
//
//* Creates a test user with role `USER`.
//
//---
//
//```java
////        UserDetails uesr2 = User
////                .withDefaultPasswordEncoder()
////                .username("manu")
////                .password("12345")
////                .roles("ADMIN")
////                .build();
//```
//
//* Creates another test user with role `ADMIN`.
//
//---
//
//```java
////        return new InMemoryUserDetailsManager(uesr1,uesr2);
//```
//
//* Returns an in-memory manager with both users.
//* Useful for testing **without a database**.
//
//---
//
//## ✅ Summary of Key Concepts
//
//| Feature                             | Description                                  |
//| ----------------------------------- | -------------------------------------------- |
//| `@EnableWebSecurity`                | Activates Spring Security                    |
//| `SecurityFilterChain`               | Main method to configure HTTP security rules |
//| `jwtFilter`                         | Custom filter to process JWT tokens          |
//| `BCryptPasswordEncoder`             | Encrypts passwords using hashing             |
//| `AuthenticationManager`             | Handles login authentication logic           |
//| `.sessionCreationPolicy(STATELESS)` | Makes it a stateless app (ideal for JWT)     |
//
//---
//
//Let me know if you'd like a **diagram** or a breakdown of how a request flows through this configuration!