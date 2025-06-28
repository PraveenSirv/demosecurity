package com.praveen.demosecurity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

//    ResponseEntity<> gives complete control over HTTP response.
//    Useful for customizing status codes, headers, and body in REST APIs.
//    Makes your API responses more flexible and RESTful.

    @GetMapping("/")
    public String greet(HttpServletRequest request){
        return "Hello world " + request.getSession().getId();
    }
}

