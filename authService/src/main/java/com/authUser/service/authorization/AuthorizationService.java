package com.authUser.service.authorization;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class AuthorizationService {

    private final AuthenticationManager authorizationManager;

    AuthorizationService ( AuthenticationManager authorizationManager){
        this.authorizationManager = authorizationManager;
    }


    @PostMapping("/login")
    public ResponseEntity<?> login (@RequestBody AuthenticationDTO dto){
        var usernamePassword = new UsernamePasswordAuthenticationToken(dto.login(), dto.password());
        var auth = this.authorizationManager.authenticate(usernamePassword);

        return ResponseEntity.ok().build();
    }

}
