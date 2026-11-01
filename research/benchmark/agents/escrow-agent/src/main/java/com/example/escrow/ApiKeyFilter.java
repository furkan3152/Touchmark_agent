package com.example.escrow;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ApiKeyFilter extends OncePerRequestFilter {
    public static final String BUYER_ATTRIBUTE = "escrow.buyer";

    private final Map<String, String> buyersByKey = new HashMap<>();

    public ApiKeyFilter(@Value("${escrow.api-keys:}") String apiKeys) {
        for (String pair : apiKeys.split(",")) {
            String[] parts = pair.trim().split(":");
            if (parts.length == 2) {
                buyersByKey.put(parts[0], parts[1]);
            }
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/inbound/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String provided = request.getHeader("X-Api-Key");
        String buyer = null;
        if (provided != null) {
            for (Map.Entry<String, String> entry : buyersByKey.entrySet()) {
                if (MessageDigest.isEqual(entry.getKey().getBytes(StandardCharsets.UTF_8),
                        provided.getBytes(StandardCharsets.UTF_8))) {
                    buyer = entry.getValue();
                }
            }
        }
        if (buyer == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "invalid api key");
            return;
        }
        request.setAttribute(BUYER_ATTRIBUTE, buyer);
        chain.doFilter(request, response);
    }
}
