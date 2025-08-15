package com.authUser.service.authorization;

import com.authUser.service.infra.TokenService;
import com.authUser.service.user.UserEntity;
import com.authUser.service.user.UserRepository;
import org.antlr.v4.runtime.Token;
import org.apache.catalina.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class AuthorizationController {

    private final AuthenticationManager authorizationManager;
    private final UserRepository repository;

    private final TokenService tokenService;


    AuthorizationController(UserRepository repository, AuthenticationManager authorizationManager, TokenService tokenService){
        this.repository = repository;
        this.authorizationManager = authorizationManager;
        this.tokenService = tokenService;
    }




    @PostMapping("/login")
    public ResponseEntity<?> login (@RequestBody AuthenticationDTO dto){
        var usernamePassword = new UsernamePasswordAuthenticationToken(dto.login(), dto.password());
        var auth = this.authorizationManager.authenticate(usernamePassword);

        var token = tokenService.generateToken((UserEntity) auth.getPrincipal());

        return ResponseEntity.ok(new AuthenticationDTOResponse(token));
    }


    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterDTO dto){
        if(repository.findByUsername(dto.username()) != null){
            return ResponseEntity.badRequest().build();
        }

        String encryptedPassword = new BCryptPasswordEncoder().encode(dto.password());
        UserEntity newUser = new UserEntity(dto.username(),dto.password(),dto.email(), dto.cpf(),dto.role());
        repository.save(newUser);

        return ResponseEntity.ok().build();


    }

}
