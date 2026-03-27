package com.example.fido2.adapter.in.web.filter;

import com.example.fido2.application.port.out.RpConfigRepository;
import com.example.fido2.domain.model.RpConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * Servlet filter that enforces HTTP Basic Auth on all {@code /api/**} endpoints.
 *
 * <p>The {@code Authorization} header must carry {@code Basic base64(rpId:rpPassword)}.
 * The rpId doubles as the identifier that selects which RP configuration to use for
 * the current request. On success the resolved {@link RpConfig} is stored as the
 * {@code rpConfig} request attribute and {@code rpId} is added to MDC.
 *
 * <p>Runs at {@code @Order(2)} — after {@link RequestLoggingFilter} (order 1) so the
 * correlation-id is already in MDC when auth-failure log lines are emitted.
 */
@Component
@Order(2)
public class FidoBasicAuthFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(FidoBasicAuthFilter.class);
    public static final String RP_CONFIG_ATTR = "rpConfig";

    private final RpConfigRepository rpConfigRepository;
    private final ObjectMapper        objectMapper;

    public FidoBasicAuthFilter(RpConfigRepository rpConfigRepository,
                                ObjectMapper objectMapper) {
        this.rpConfigRepository = rpConfigRepository;
        this.objectMapper        = objectMapper;
    }

    @Override
    public void doFilter(ServletRequest servletRequest,
                          ServletResponse servletResponse,
                          FilterChain chain) throws IOException, ServletException {

        HttpServletRequest  req = (HttpServletRequest)  servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        if (!isApiRequest(req)) {
            chain.doFilter(servletRequest, servletResponse);
            return;
        }

        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            log.warn("Missing or non-Basic Authorization header for {} {}", req.getMethod(), req.getRequestURI());
            sendUnauthorized(res, "Missing or invalid Authorization header");
            return;
        }

        String decoded;
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(authHeader.substring(6).trim());
            decoded = new String(decodedBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            log.warn("Malformed Base64 in Authorization header");
            sendUnauthorized(res, "Malformed Authorization header");
            return;
        }

        int colon = decoded.indexOf(':');
        if (colon <= 0) {
            log.warn("Authorization header does not contain rpId:password pair");
            sendUnauthorized(res, "Malformed Authorization header");
            return;
        }

        String rpId     = decoded.substring(0, colon);
        String password = decoded.substring(colon + 1);

        RpConfig rpConfig = rpConfigRepository.findActiveByRpId(rpId)
                .filter(r -> r.getRpPassword().equals(password))
                .orElse(null);

        if (rpConfig == null) {
            log.warn("Authentication failed for rpId='{}'", rpId);
            sendUnauthorized(res, "Invalid RP credentials");
            return;
        }

        MDC.put("rpId", rpId);
        req.setAttribute(RP_CONFIG_ATTR, rpConfig);

        log.debug("Authenticated RP: rpId='{}'", rpId);
        chain.doFilter(servletRequest, servletResponse);
    }

    private boolean isApiRequest(HttpServletRequest req) {
        return req.getRequestURI().startsWith("/api/");
    }

    private void sendUnauthorized(HttpServletResponse res, String detail) throws IOException {
        res.setStatus(HttpStatus.UNAUTHORIZED.value());
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.setCharacterEncoding(StandardCharsets.UTF_8.name());

        Map<String, Object> body = Map.of(
                "type",      "about:blank",
                "title",     "Unauthorized",
                "status",    HttpStatus.UNAUTHORIZED.value(),
                "detail",    detail,
                "timestamp", Instant.now().toString()
        );
        objectMapper.writeValue(res.getWriter(), body);
    }
}
