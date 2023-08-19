package com.cmk.userauth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.cmk.userauth.entity.User;
import com.cmk.userauth.repository.UserRepository;

@RestController
public class AuthController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;
    
    @PostMapping("/auth/register")
    public ResponseEntity<?> registerUser(@RequestBody User user){
        
        if(userRepository.existsByUsername(user.getUsername())){
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }

        User newUser = new User();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(passwordEncoder.encode(user.getPassword()));

        userRepository.save(newUser);
        
        return ResponseEntity.ok("User registered successfully!");
    }

}
