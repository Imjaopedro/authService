package com.authUser.service.infra;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.authUser.service.user.UserEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.token.security}")
    private String secret;

    public String generateToken(UserEntity user){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret);
            String token = JWT.create()
                    .withIssuer("authAPI")
                    .withSubject(user.getUsername())
                    .withExpiresAt(generateExpirationDate())
                    .sign(algorithm);
            return token;
        }catch (JWTCreationException e){
            throw new RuntimeException("Error to generate token", e);
        }
    }


    private String validateToken(String token){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("authAPI")
                    .build()
                    .verify(token)
                    .getSubject();
        }catch (JWTVerificationException e){
            throw new RuntimeException("error validate token", e);
        }
    }

    private Instant generateExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
