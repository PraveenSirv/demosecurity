package com.praveen.demosecurity.config;

import com.praveen.demosecurity.jwt.JWTService;
import com.praveen.demosecurity.service.MyUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    ApplicationContext context;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if(authHeader != null && authHeader.startsWith("Bearer ")){
            token = authHeader.substring(7);
            username = jwtService.extractUserName(token);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = context.getBean(MyUserDetails.class).loadUserByUsername(username);
            if (jwtService.validToken(token, userDetails)){
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}


//Here is a **line-by-line explanation** of your custom JWT filter class in Spring Security:
//
//---
//
//## ✅ Class Definition
//
//```java
//@Component
//public class JwtFilter extends OncePerRequestFilter {
//```
//
//* `@Component`: Marks this class as a Spring-managed bean (auto-detect via component scan).
//* `OncePerRequestFilter`: Ensures this filter is executed **once per HTTP request**, unlike generic filters that may be reused.
//
//---
//
//## 🔧 Autowired Dependencies
//
//```java
//@Autowired
//private JWTService jwtService;
//```
//
//* Injects a service that handles JWT operations like extracting username, validating tokens, etc.
//
//```java
//@Autowired
//ApplicationContext context;
//```
//
//* Injects the **Spring context** to get beans manually, in this case to load user details dynamically.
//
//---
//
//## 🔁 Core Logic in `doFilterInternal(...)`
//
//```java
//@Override
//protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//        throws ServletException, IOException {
//```
//
//* Overridden method where filter logic is implemented.
//* `request` and `response`: standard HTTP request and response objects.
//* `filterChain`: used to pass the request to the next filter in the chain.
//
//---
//
//## 🔍 Step 1: Extract Authorization Header
//
//```java
//String authHeader = request.getHeader("Authorization");
//String token = null;
//String username = null;
//```
//
//* Grabs the `Authorization` header (e.g., `"Bearer eyJhbGciOi..."`).
//
//```java
//if(authHeader != null && authHeader.startsWith("Bearer ")){
//    token = authHeader.substring(7);
//    username = jwtService.extractUserName(token);
//}
//```
//
//* Checks if header exists and starts with `"Bearer "`.
//* Extracts the **JWT token** and **username** from it using `jwtService`.
//
//---
//
//## 🔐 Step 2: Validate and Authenticate
//
//```java
//if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
//```
//
//* Ensures:
//
//  * A username was successfully extracted.
//  * No user is already authenticated for this request (to prevent re-authentication).
//
//```java
//UserDetails userDetails = context.getBean(MyUserDetails.class).loadUserByUsername(username);
//```
//
//* Dynamically loads user details using a custom `UserDetailsService` (`MyUserDetails`).
//* You are retrieving the bean from the Spring `ApplicationContext`.
//
//```java
//if (jwtService.validToken(token, userDetails)){
//```
//
//* Validates the token against user details (e.g., expiry date, signature match, etc.).
//
//---
//
//## ✅ Step 3: Set Authentication in Security Context
//
//```java
//UsernamePasswordAuthenticationToken authToken =
//        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//```
//
//* Creates an authentication object that Spring Security understands.
//* `userDetails`: principal
//* `null`: no credentials (JWT already authenticated)
//* `getAuthorities()`: roles or permissions of the user
//
//```java
//authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//```
//
//* Adds extra details about the request (like remote IP, session ID).
//
//```java
//SecurityContextHolder.getContext().setAuthentication(authToken);
//```
//
//* Stores the authentication in the current **security context**, making the user officially "logged in".
//
//---
//
//## ⏭️ Step 4: Continue Filter Chain
//
//```java
//filterChain.doFilter(request, response);
//```
//
//* Passes control to the **next filter** or endpoint handler.
//
//---
//
//## ✅ Summary of Flow
//
//1. Read `Authorization` header.
//2. If it contains a valid JWT:
//
//   * Extract username.
//   * Validate token.
//   * Load user details.
//   * Set user as authenticated in `SecurityContext`.
//3. Pass the request forward in the chain.
//
//---
//
//## 🔒 Why This Is Important
//
//* Ensures **stateless authentication** using JWT.
//* Bypasses session login by checking the token **on every request**.
//* Integrates cleanly with Spring Security by populating the `SecurityContextHolder`.
//
//---
//
//Let me know if you want a diagram showing the full request flow: Client → JWTFilter → SecurityContext → Controller!