package com.devalz.xssprotection.api;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
public class XssSanitizeController {

    @PostMapping("/sanitize-body")
    public ResponseEntity<?> sanitizeBody(@RequestBody SampleDto sampleDto) {
        return new ResponseEntity<>(sampleDto, HttpStatus.OK);
    }

    //set request content type to multipart/form-data.
    //set content type of the data part to application/JSON.
    @PostMapping(value = "/sanitize-parts", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<?> sanitizeParts(@RequestPart("data") SampleDto sampleDto,
                                           @RequestPart("file") MultipartFile file) {
        return new ResponseEntity<>(sampleDto, HttpStatus.OK);
    }

    @GetMapping("/sanitize-headers")
    public ResponseEntity<?> sanitizeHeaders() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getRequest();
        return new ResponseEntity<>(request.getHeader("header-key"), HttpStatus.OK);
    }

    @GetMapping("/sanitize-path-variables/{pathVariable}")
    public ResponseEntity<?> sanitizePathVariables(@PathVariable String pathVariable) {
        return new ResponseEntity<>(pathVariable, HttpStatus.OK);
    }

    @GetMapping(value = "/sanitize-request-params")
    public ResponseEntity<?> sanitizeRequestParams(@RequestParam String requestParam) {
        return new ResponseEntity<>(requestParam, HttpStatus.OK);
    }
}
