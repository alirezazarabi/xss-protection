package com.devalz.xssprotection.utils;

import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.Charset;

public class HttpServletRequestUtils {

    public static String getCharacterEncoding(HttpServletRequest request) {
        return StringUtils.hasText(request.getCharacterEncoding()) ?
                request.getCharacterEncoding() : Charset.defaultCharset().name();
    }

}
