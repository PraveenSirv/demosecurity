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
