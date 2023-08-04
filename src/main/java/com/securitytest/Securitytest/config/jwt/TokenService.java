package com.securitytest.Securitytest.config.jwt;

import com.securitytest.Securitytest.DTO.TokenDTO;
import com.securitytest.Securitytest.auth.PrincipalDetails;
import com.securitytest.Securitytest.model.Entity.User;
import com.securitytest.Securitytest.model.Repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenService implements InitializingBean {
    private final UserRepository usersrepository;

    private final Logger logger = LoggerFactory.getLogger(TokenService.class);
    private static final String AUTHORITIES_KEY = "auth";
    private final String secret;
    private final long accessTokenValidityInMilliseconds;

    private final long refreshTokenValidityInMilliseconds;

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String REFRESHTOKEN_HEADER = "RefreshToken";
    private Key key;

    public TokenService(
            UserRepository usersrepository, @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.usersrepository = usersrepository;
        this.secret = secret;
        this.accessTokenValidityInMilliseconds = tokenValidityInSeconds * 500;
        this.refreshTokenValidityInMilliseconds = tokenValidityInSeconds * 1000 * 336;
    }

    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }


    public TokenDTO createToken(PrincipalDetails principalDetails) {
        return createToken(principalDetails.getUsername(), principalDetails.getAuthorities());
    }

    public TokenDTO createToken(String name, Collection<? extends GrantedAuthority> inputAuthorities) {
        String authorities = inputAuthorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();

        String accessToken = Jwts.builder()
                .setSubject(name)
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(new Date(now + this.accessTokenValidityInMilliseconds))
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(name)
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(new Date(now + this.refreshTokenValidityInMilliseconds))
                .compact();

        return TokenDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentication(User user) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        PrincipalDetails principal = new PrincipalDetails(user);

        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
    }

    public String resolveRefreshToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(REFRESHTOKEN_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("worng JWT sign");
        } catch (ExpiredJwtException e) {
            logger.info("expire JWT");
        } catch (UnsupportedJwtException e) {
            logger.info("No support JWT");
        } catch (IllegalArgumentException e) {
            logger.info("JWT is worng");
        }
        return false;
    }

}