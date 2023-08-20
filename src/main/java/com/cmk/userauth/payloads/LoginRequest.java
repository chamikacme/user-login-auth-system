package com.cmk.userauth.payloads;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
