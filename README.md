# Cross-site scripting (XSS)  
XSS is one of the most serious web application security vulnerabilities from OWASP point of view.

## How do we protect ourselves from these attacks?
escape or sanitize any characters that could be interpreted as code by the browser or the server.

## How to implement for spring restful applications?
This is an implementation that sanitizes __request components(body, parts, headers, path variables, and request params)__.

### OWASP top ten:
https://owasp.org/www-project-top-ten/







