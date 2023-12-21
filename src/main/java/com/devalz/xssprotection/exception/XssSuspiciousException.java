package com.devalz.xssprotection.exception;

public class XssSuspiciousException extends RuntimeException {

    public XssSuspiciousException() {
        super();
    }

    public XssSuspiciousException(String message) {
        super(message);
    }

    public XssSuspiciousException(String message, Throwable cause) {
        super(message, cause);
    }
}
