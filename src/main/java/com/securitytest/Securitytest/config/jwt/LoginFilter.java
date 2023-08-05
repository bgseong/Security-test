package com.securitytest.Securitytest.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securitytest.Securitytest.DTO.LoginRequestDTO;
import com.securitytest.Securitytest.DTO.TokenDTO;
import com.securitytest.Securitytest.auth.PrincipalDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter{
    private final AuthenticationManager authenticationManager;

    @Autowired
    TokenService tokenService;
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        ObjectMapper om = new ObjectMapper();
        LoginRequestDTO loginRequestDto = null;
        try {
            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDTO.class);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println(loginRequestDto.getEmail());
        System.out.println(loginRequestDto.getPassword());
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginRequestDto.getEmail(),
                        loginRequestDto.getPassword());

        System.out.println("JwtAuthenticationFilter : 토큰생성완료");

        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        return authentication;

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("인증성공");
        PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();
        String accessToken = tokenService.createAccessToken(principalDetailis);
        String refreshToken = tokenService.createRefreshToken(principalDetailis);
        response.setHeader("Authorization", "bearer " + accessToken);
        response.setHeader("RefreshToken", "bearer " + refreshToken);


    }
}
