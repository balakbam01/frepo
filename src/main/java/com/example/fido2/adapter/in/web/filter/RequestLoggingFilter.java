package com.example.fido2.adapter.in.web.filter;

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
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

/**
 * Servlet filter that:
 * <ul>
 *   <li>Assigns a correlation ID to every request (from {@code X-Correlation-Id} header
 *       or generated fresh) and propagates it via MDC.</li>
 *   <li>Logs method, URI, and response status with elapsed time for every API call.</li>
 * </ul>
 */
@Component
@Order(1)
public class RequestLoggingFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    public void doFilter(ServletRequest servletRequest,
                          ServletResponse servletResponse,
                          FilterChain chain) throws IOException, ServletException {

        HttpServletRequest  req = (HttpServletRequest)  servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        String correlationId = req.getHeader("X-Correlation-Id");
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }

        MDC.put("correlationId", correlationId);
        res.setHeader("X-Correlation-Id", correlationId);

        long start = System.currentTimeMillis();
        try {
            if (isApiRequest(req)) {
                log.info("→ {} {} [correlationId={}]",
                        req.getMethod(), req.getRequestURI(), correlationId);
            }

            chain.doFilter(servletRequest, servletResponse);

        } finally {
            long elapsed = System.currentTimeMillis() - start;
            if (isApiRequest(req)) {
                log.info("← {} {} {} {}ms",
                        req.getMethod(), req.getRequestURI(), res.getStatus(), elapsed);
            }
            MDC.clear();
        }
    }

    private boolean isApiRequest(HttpServletRequest req) {
        return req.getRequestURI().startsWith("/api/");
    }
}
