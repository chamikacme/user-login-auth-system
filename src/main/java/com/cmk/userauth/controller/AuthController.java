package com.cmk.userauth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.cmk.userauth.entity.User;
import com.cmk.userauth.payloads.JwtResponse;
import com.cmk.userauth.payloads.LoginRequest;
import com.cmk.userauth.payloads.MessageResponses;
import com.cmk.userauth.repository.UserRepository;
import com.cmk.userauth.security.jwt.JwtUtils;

@RestController
public class AuthController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;
    
    @PostMapping("/auth/register")
    public ResponseEntity<?> registerUser(@RequestBody User user){
        
        if(userRepository.existsByUsername(user.getUsername())){
            return ResponseEntity.badRequest().body(new MessageResponses("Error: Username is already taken!"));
        }

        User newUser = new User();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(passwordEncoder.encode(user.getPassword()));

        userRepository.save(newUser);

        return ResponseEntity.ok(new MessageResponses("User registered successfully!"));
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);

        User user = userRepository.findByUsername(loginRequest.getUsername()).get();
        
        return ResponseEntity.ok(new JwtResponse(jwt, user.getId(), user.getUsername()));
    }

}
