package com.securitytest.Securitytest.DTO;

import jakarta.persistence.Column;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class LoginRequestDTO {

    private String email;

    private String password;
}
