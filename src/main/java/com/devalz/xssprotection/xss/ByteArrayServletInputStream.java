package com.devalz.xssprotection.xss;

import org.springframework.util.Assert;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class ByteArrayServletInputStream extends ServletInputStream {

    private final ByteArrayInputStream byteArrayInputStream;
    private boolean finished = false;

    public ByteArrayServletInputStream(byte[] input) {
        super();
        Assert.notNull(input, "input is null");
        this.byteArrayInputStream = new ByteArrayInputStream(input);
    }

    @Override
    public int read() throws IOException {
        int data = this.byteArrayInputStream.read();
        if (data == -1) {
            this.finished = true;
        }
        return data;
    }

    @Override
    public boolean isFinished() {
        return this.finished;
    }

    @Override
    public boolean isReady() {
        //return false for blocking IO.
        return false;
    }

    @Override
    public void setReadListener(ReadListener listener) {
        //don't need to implement for blocking IO.
    }

}
