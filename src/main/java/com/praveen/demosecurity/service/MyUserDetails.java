package com.praveen.demosecurity.service;

import com.praveen.demosecurity.model.UserPrincipal;
import com.praveen.demosecurity.model.Users;
import com.praveen.demosecurity.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetails implements UserDetailsService {
    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user1 = userRepo.findByUsername(username);
        return new UserPrincipal(user1);
    }
}



//Here's a **line-by-line explanation** of your `MyUserDetails` class, which is a custom implementation of Spring Security’s `UserDetailsService` interface:
//
//---
//
//## ✅ Class and Annotation
//
//```java
//@Service
//public class MyUserDetails implements UserDetailsService {
//```
//
//* `@Service`: Marks this class as a Spring-managed service, allowing it to be injected wherever needed.
//* `UserDetailsService`: This is a Spring Security interface used to **load user-specific data** (like username, password, roles) during authentication.
//
//---
//
//## 🔧 Injecting User Repository
//
//```java
//@Autowired
//private UserRepo userRepo;
//```
//
//* Injects your custom repository (`UserRepo`) used to fetch user data from a database.
//* `UserRepo` likely extends `JpaRepository<Users, Long>` and defines a method like:
//
//  ```java
//  Users findByUsername(String username);
//  ```
//
//---
//
//## 🔑 Core Authentication Method
//
//```java
//@Override
//public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//```
//
//* This method is called automatically by Spring Security when a user tries to log in.
//* It takes a username and attempts to fetch the corresponding user data from your database.
//
//```java
//Users user1 = userRepo.findByUsername(username);
//```
//
//* Calls the repository method to retrieve a `Users` object (a custom entity class) by the given username.
//
//```java
//return new UserPrincipal(user1);
//```
//
//* Wraps the retrieved user entity in a custom `UserPrincipal` class that implements `UserDetails`.
//* This `UserPrincipal` class should override methods like `getUsername()`, `getPassword()`, and `getAuthorities()` to provide Spring Security the necessary user credentials and roles.
//
//---
//
//## ✅ Summary
//
//| Component              | Role                                                      |
//| ---------------------- | --------------------------------------------------------- |
//| `MyUserDetails`        | Loads user info from DB to be used in authentication      |
//| `UserDetailsService`   | Spring Security interface implemented here                |
//| `loadUserByUsername()` | Used by Spring to fetch user details by username          |
//| `UserPrincipal`        | Adapts your `Users` entity to Spring's `UserDetails` type |
//
//---
//
//### ✅ Example Flow During Login:
//
//1. A login request is made with a username.
//2. Spring calls `loadUserByUsername(username)`.
//3. This method uses `UserRepo` to fetch the user.
//4. Returns a `UserPrincipal` containing user credentials and roles.
//5. Spring Security uses this to validate the password and set up authentication.
//
//---
//
//Would you like a sample `UserPrincipal` class as well for clarity?