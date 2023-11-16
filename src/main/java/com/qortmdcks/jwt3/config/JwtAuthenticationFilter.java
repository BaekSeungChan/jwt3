package com.qortmdcks.jwt3.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component  // 스프링 컴포넌트로 선언, 스프링이 관리하게 됩니다.
@RequiredArgsConstructor  // Lombok 라이브러리를 사용하여 생성자 주입을 위한 코드를 자동으로 생성합니다.
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;  // JwtService 주입, JWT 관련 작업을 위해 사용됩니다.

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // HTTP 요청에서 'Authorization' 헤더를 가져옵니다.
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // 'Authorization' 헤더가 없거나 'Bearer'로 시작하지 않으면 요청을 계속 진행시킵니다.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 헤더에서 JWT를 추출합니다 ('Bearer ' 다음 부분).
        jwt = authHeader.substring(7);

        // JwtService를 사용하여 토큰에서 사용자 이메일(또는 사용자 이름)을 추출합니다.
        userEmail = jwtService.extractUsername(jwt);

        // TODO: 여기서 JWT의 유효성을 검증하고 사용자 인증 로직을 추가해야 합니다.
        // 예를 들어, 토큰의 만료 여부, 서명의 유효성 등을 검사할 수 있습니다.
    }
}
