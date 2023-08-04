package com.securitytest.Securitytest.DTO;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class TokenDTO {
    private String accessToken;

    private String refreshToken;

}
