package com.praveen.demosecurity.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {

    private String secretkey = "";

    public JWTService() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("HmacSHA256");
        SecretKey key = keygen.generateKey();
        secretkey = Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public String generateToken(String username) {
        Map<String,Object> claims = new HashMap<>();
        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 60*60*60*30))
                .and()
                .signWith(getKey())
                .compact();
    }

    private SecretKey getKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretkey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims,T>claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }
}


//Here's a **line-by-line explanation** of your `JWTService` class, which is responsible for generating and validating **JWT tokens** in a Spring Security application:
//
//---
//
//## ✅ Class & Annotation
//
//```java
//@Service
//public class JWTService {
//```
//
//* `@Service`: Marks this class as a Spring **service component**, enabling it to be injected with `@Autowired`.
//* Responsible for handling **JWT logic** like token creation, validation, and extracting claims.
//
//---
//
//## 🔐 Secret Key Generation
//
//```java
//private String secretkey = "";
//```
//
//* Holds the **base64-encoded secret key** used for signing and verifying tokens.
//
//```java
//public JWTService() throws NoSuchAlgorithmException {
//    KeyGenerator keygen = KeyGenerator.getInstance("HmacSHA256");
//    SecretKey key = keygen.generateKey();
//    secretkey = Base64.getEncoder().encodeToString(key.getEncoded());
//}
//```
//
//* Constructor that:
//
//  * Creates a new **HMAC SHA-256** secret key.
//  * Encodes it to Base64 so it can be safely stored/used later.
//
//> ⚠️ Note: In real-world applications, this key should be fixed and loaded from a **secure config file or environment variable** (not randomly regenerated on each startup).
//
//---
//
//## 🔧 Token Generation
//
//```java
//public String generateToken(String username) {
//    Map<String,Object> claims = new HashMap<>();
//```
//
//* Starts building a JWT with optional **custom claims** (empty for now).
//
//```java
//return Jwts.builder()
//        .claims()
//        .add(claims)
//        .subject(username)
//        .issuedAt(new Date(System.currentTimeMillis()))
//        .expiration(new Date(System.currentTimeMillis() + 60*60*60*30))
//        .and()
//        .signWith(getKey())
//        .compact();
//```
//
//* Creates a token:
//
//  * `subject(username)`: Stores the username as the **subject** of the token.
//  * `issuedAt(...)`: Token creation time.
//  * `expiration(...)`: Sets expiration (here it's `~75 hours`).
//  * `signWith(...)`: Signs the token with the HMAC key.
//  * `compact()`: Serializes the JWT into a string.
//
//---
//
//## 🔐 Get Signing Key
//
//```java
//private SecretKey getKey(){
//    byte[] keyBytes = Decoders.BASE64.decode(secretkey);
//    return Keys.hmacShaKeyFor(keyBytes);
//}
//```
//
//* Decodes the Base64 string back into bytes.
//* Creates a **SecretKey** for HMAC-SHA signing/verification.
//
//---
//
//## 🧾 Extract Claims & Username
//
//```java
//public String extractUserName(String token) {
//    return extractClaim(token, Claims::getSubject);
//}
//```
//
//* Extracts the **username (subject)** from the token.
//
//```java
//private <T> T extractClaim(String token, Function<Claims,T> claimResolver) {
//    final Claims claims = extractAllClaims(token);
//    return claimResolver.apply(claims);
//}
//```
//
//* General-purpose method to extract any claim from the token (subject, expiration, etc.).
//
//```java
//private Claims extractAllClaims(String token) {
//    return Jwts.parser()
//            .verifyWith(getKey())
//            .build()
//            .parseSignedClaims(token)
//            .getPayload();
//}
//```
//
//* Parses the token and validates it using the secret key.
//* Returns the **payload (claims)** for further processing.
//
//---
//
//## ✅ Validate Token
//
//```java
//public boolean validToken(String token, UserDetails userDetails) {
//    final String userName = extractUserName(token);
//    return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
//}
//```
//
//* Compares the extracted username with the authenticated user.
//* Also checks if the token is **not expired**.
//
//---
//
//## ⏳ Expiration Check
//
//```java
//private boolean isTokenExpired(String token) {
//    return extractExpiration(token).before(new Date());
//}
//```
//
//```java
//private Date extractExpiration(String token) {
//    return extractClaim(token, Claims::getExpiration);
//}
//```
//
//* Extracts expiration date from the token.
//* Checks whether the token is expired.
//
//---
//
//## ✅ Summary of Responsibilities
//
//| Method              | Purpose                                               |
//| ------------------- | ----------------------------------------------------- |
//| `generateToken()`   | Create a signed JWT token for a username              |
//| `extractUserName()` | Get the username from a token                         |
//| `validToken()`      | Check if the token is valid for a given user          |
//| `extractClaim()`    | Generic claim extractor using a lambda function       |
//| `isTokenExpired()`  | Verifies if the token is still valid in terms of time |
//
//---
//
//## ⚠️ Suggestions for Production
//
//1. **Persist the secret key** securely — do not regenerate it on every restart.
//2. **Add roles/authorities** to the token as claims, if needed.
//3. **Add exception handling** for invalid/malformed tokens.
//
//---
//
//Would you like me to generate a diagram showing how this `JWTService` fits in with your `JwtFilter` and `SecurityConfig` classes?
