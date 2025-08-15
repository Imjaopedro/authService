package com.authUser.service.authorization;

import com.authUser.service.user.RoleEnum;

public record RegisterDTO(String username, String password, RoleEnum role, String email, String cpf) {
}
