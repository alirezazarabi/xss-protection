package com.devalz.xssprotection;

import com.devalz.xssprotection.api.SampleDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class XssProtectionApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    @Test
    void sanitizeBody_scriptInbody_escapedBodyCharacter() throws Exception {
        String requestBody = objectMapper.writeValueAsString(new SampleDto("<script>alert(‘XSS’)</script>"));
        MockHttpServletRequestBuilder requestBuilder =
                post("/api/sanitize-body")
                        .content(requestBody)
                        .contentType(MediaType.APPLICATION_JSON);
        String expectedJsonResponse =
                objectMapper.writeValueAsString(new SampleDto("&lt;script&gt;alert(‘XSS’)&lt;/script&gt;"));
        this.mockMvc.perform(requestBuilder)
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().json(expectedJsonResponse));
    }

    //todo complete tests
}
