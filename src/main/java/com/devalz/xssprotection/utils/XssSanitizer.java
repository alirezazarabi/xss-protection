package com.devalz.xssprotection.utils;

import org.springframework.util.StringUtils;

public class XssSanitizer {

    public static String sanitize(String input) {
        if (!StringUtils.hasText(input)) {
            return input;
        }
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    public static boolean hasSpecialCharacter(String input) {
        if (!StringUtils.hasText(input)) {
            return false;
        }
        return input.contains("&") ||
                input.contains("<") ||
                input.contains(">");
    }

}


