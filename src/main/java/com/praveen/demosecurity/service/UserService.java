package com.praveen.demosecurity.service;

import com.praveen.demosecurity.jwt.JWTService;
import com.praveen.demosecurity.model.Users;
import com.praveen.demosecurity.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private JWTService jwtService;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public Users register(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    public String verify(Users user) {
        Authentication authentication = authenticationManager.authenticate
                (new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));

        if (authentication.isAuthenticated())
            return jwtService.generateToken(user.getUsername());
        return "fail";
    }
}


//Here's a **line-by-line explanation** of your `UserService` class — this class handles user registration and authentication using Spring Security and JWT.
//
//---
//
//## ✅ Class & Dependencies
//
//```java
//@Service
//public class UserService {
//```
//
//* `@Service`: Marks the class as a Spring **service component**, making it eligible for dependency injection.
//
//---
//
//### 🔧 Dependencies
//
//```java
//@Autowired
//private UserRepo userRepo;
//```
//
//* Injects your repository used for accessing and saving `Users` objects to the database.
//
//```java
//@Autowired
//AuthenticationManager authenticationManager;
//```
//
//* The **Spring Security component** responsible for authenticating user credentials.
//
//```java
//@Autowired
//private JWTService jwtService;
//```
//
//* Injects the service that handles JWT token generation and validation.
//
//```java
//private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
//```
//
//* Creates a password encoder with strength **12**, used to **hash user passwords** before saving them.
//
//---
//
//## 📝 Method: Register a New User
//
//```java
//public Users register(Users user) {
//    user.setPassword(encoder.encode(user.getPassword()));
//    return userRepo.save(user);
//}
//```
//
//### Explanation:
//
//* Accepts a new `Users` object (likely from a REST API).
//* Uses `BCryptPasswordEncoder` to securely **hash the plain-text password**.
//* Saves the user to the database using `userRepo.save(user)`.
//* Returns the saved user (optionally useful for confirmation or debugging).
//
//---
//
//## 🔐 Method: Verify & Login (Authenticate + JWT)
//
//```java
//public String verify(Users user) {
//    Authentication authentication = authenticationManager.authenticate(
//        new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
//    );
//```
//
//* Creates a `UsernamePasswordAuthenticationToken` using username and password provided by the user.
//* Passes it to the `authenticationManager` to **authenticate**.
//
//  * Spring will internally call your `MyUserDetails` → `loadUserByUsername()` → validate password.
//
//```java
//if (authentication.isAuthenticated())
//    return jwtService.generateToken(user.getUsername());
//```
//
//* If authentication is successful:
//
//  * Generate a **JWT token** using the `username`.
//
//```java
//return "fail";
//```
//
//* If not authenticated, return `"fail"`.
//
//---
//
//## ✅ Summary of Responsibilities
//
//| Method       | Description                                      |
//| ------------ | ------------------------------------------------ |
//| `register()` | Hashes password and saves new user to DB         |
//| `verify()`   | Authenticates user and returns JWT if successful |
//
//---
//
//## 🔐 Login & Token Flow
//
//1. `POST /register` → Calls `register()` → Saves user with hashed password.
//2. `POST /login` → Calls `verify()`:
//
//   * Authenticates credentials via Spring Security.
//   * On success, returns a signed **JWT token**.
//3. The token can be used in the `Authorization` header for secured routes.
//
//---
//
//Would you like a sample REST controller (`UserController`) that uses these `register()` and `verify()` methods?
