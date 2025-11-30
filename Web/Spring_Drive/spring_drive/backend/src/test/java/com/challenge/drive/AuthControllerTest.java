package com.challenge.drive;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.challenge.drive.controller.AuthController;
import com.challenge.drive.dto.LoginDto;
import com.challenge.drive.dto.RegisterDto;
import com.challenge.drive.model.UserModel;
import com.challenge.drive.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
public class AuthControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private UserService userService;

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Test
    void registerTest() throws Exception {
        String username = "test";
        String email = "test@example.com";
        String password = "password";

        RegisterDto registerDto = new RegisterDto(username, email, password, password);

        UserModel user = new UserModel();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(password);

        when(userService.saveUser(any(UserModel.class))).thenReturn(user);

        this.mvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

    @Test
    void loginTest() throws Exception {
        String username = "test";
        String email = "test@example.com";
        String password = "password";

        LoginDto loginDto = new LoginDto(username, password);

        UserModel user = new UserModel();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(password);

        when(userService.findByUsernameAndPassword(username, password)).thenReturn(user);

        this.mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));
    }

}
