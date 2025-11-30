package com.challenge.drive.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.challenge.drive.dto.JSendDto;
import com.challenge.drive.service.UserService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthenticationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Autowired
    private UserService userService;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        HttpSession session = httpRequest.getSession();
        if (session != null) {
            Integer userId = (Integer) session.getAttribute("userId");
            if (userId != null && userService.findUserById((int)userId) != null) {
                chain.doFilter(request, response);
                return;
            }
        }

        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.setContentType("application/json");
        JSendDto failResponse = JSendDto.fail("Not logged in");
        httpResponse.getWriter().write(objectMapper.writeValueAsString(failResponse));
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
