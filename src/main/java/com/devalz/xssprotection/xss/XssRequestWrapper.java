package com.devalz.xssprotection.xss;

import com.devalz.xssprotection.exception.XssSuspiciousException;
import com.devalz.xssprotection.utils.HttpServletRequestUtils;
import com.devalz.xssprotection.utils.XssSanitizer;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.Part;
import org.apache.commons.io.IOUtils;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collection;

public class XssRequestWrapper extends HttpServletRequestWrapper {

    private ServletInputStream servletInputStream;

    public XssRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        this.servletInputStream = request.getInputStream();

        if (request.getContentType() != null &&
                request.getContentType().toLowerCase().contains(MediaType.APPLICATION_JSON_VALUE)) {
            String body = IOUtils.toString(request.getInputStream(),
                    HttpServletRequestUtils.getCharacterEncoding(request));
            if (StringUtils.hasText(body)) {
                body = XssSanitizer.sanitize(body);
                this.servletInputStream = new ByteArrayServletInputStream(body.getBytes());
            }
        }
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return this.servletInputStream;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(this.getInputStream()));
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException {
        Collection<Part> parts = super.getParts();
        if (!CollectionUtils.isEmpty(parts)) {
            parts = parts.stream().map(this::modifyPart).toList();
        }
        return parts;
    }

    @Override
    public Part getPart(String name) throws IOException, ServletException {
        Part part = super.getPart(name);
        if (part != null) {
            part = modifyPart(part);
        }
        return part;
    }

    @Override
    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
        if (values == null) {
            return null;
        }
        int count = values.length;
        String[] encodedValues = new String[count];
        for (int i = 0; i < count; i++) {
            encodedValues[i] = XssSanitizer.sanitize(values[i]);
        }
        return encodedValues;
    }

    @Override
    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
        return XssSanitizer.sanitize(value);
    }

    @Override
    public String getRequestURI() {
        String requestURI = super.getRequestURI();
        //semicolon(‘;’) used for delimiting variables.so can't sanitize.
        boolean hasSpecialCharacter = XssSanitizer.hasSpecialCharacter(requestURI);
        if (hasSpecialCharacter){
            throw new XssSuspiciousException("suspected to xss attack");
        }
        return requestURI;
    }

    @Override
    public String getQueryString() {
        String queryString = super.getQueryString();
        if (!StringUtils.hasText(queryString)) {
            return queryString;
        }
        String characterEncoding = HttpServletRequestUtils.getCharacterEncoding((HttpServletRequest) getRequest());
        String decodedQueryString = UriUtils.decode(queryString, characterEncoding);
        decodedQueryString = XssSanitizer.sanitize(decodedQueryString);
        return UriUtils.encodeQuery(decodedQueryString, characterEncoding);
    }

    @Override
    public String getHeader(String name) {
        return XssSanitizer.sanitize(super.getHeader(name));
    }

    private Part modifyPart(Part part) {
        Assert.notNull(part, "part is null");
        if (part.getContentType() != null &&
                part.getContentType().toLowerCase().contains(MediaType.APPLICATION_JSON_VALUE)) {
            String characterEncoding = HttpServletRequestUtils.getCharacterEncoding((HttpServletRequest) getRequest());
            return new XssProtectedPart(part, characterEncoding);
        }
        return part;
    }

}
