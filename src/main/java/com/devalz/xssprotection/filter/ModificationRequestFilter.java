package com.devalz.xssprotection.filter;

import com.devalz.xssprotection.exception.XssSuspiciousException;
import com.devalz.xssprotection.xss.XssRequestWrapper;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class ModificationRequestFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            XssRequestWrapper wrappedRequest = new XssRequestWrapper((HttpServletRequest) request);
            chain.doFilter(wrappedRequest, response);
        } catch (XssSuspiciousException e) {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        }
    }

}
