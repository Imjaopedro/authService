package com.authUser.service.domain.user;

public record RegisterDTO(String login, String password, UserRole role) {
}
