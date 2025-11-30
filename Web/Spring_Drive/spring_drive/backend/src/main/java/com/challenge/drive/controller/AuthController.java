package com.challenge.drive.controller;

import com.challenge.drive.config.Constants;
import com.challenge.drive.dto.*;
import com.challenge.drive.model.UserModel;
import com.challenge.drive.service.UserService;
import com.challenge.drive.util.ResetPasswordStorage;
import com.challenge.drive.util.ResetPasswordToken;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public JSendDto login(@Valid @RequestBody LoginDto loginDto, BindingResult bindingResult, HttpSession session) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(", "));
            return JSendDto.fail("Validation failed: " + errorMessage);
        }

        String username = loginDto.username();
        String password = loginDto.password();

        UserModel user = userService.findByUsernameAndPassword(username, password);
        if (user == null) {
            return JSendDto.fail("Invalid username or password");
        }

        session.setAttribute("userId", user.getId());
        return JSendDto.success("Login successful");
    }

    @PostMapping("/register")
    public JSendDto register(@Valid @RequestBody RegisterDto registerDto, BindingResult bindingResult, HttpSession session) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(", "));
            return JSendDto.fail("Validation failed: " + errorMessage);
        }

        String username = registerDto.username();
        String email = registerDto.email();
        String password = registerDto.password();
        String confirmPassword = registerDto.confirmPassword();

        if (!password.equals(confirmPassword)) {
            return JSendDto.fail("Passwords must match");
        }

        if (userService.findByUsername(username) != null) {
            return JSendDto.fail("Username already exists");
        }

        if (userService.findByEmail(email) != null) {
            return JSendDto.fail("Email already exists");
        }

        UserModel user = new UserModel();
        user.setUsername(username);
        user.setPassword(password);
        user.setEmail(email);

        if (userService.saveUser(user) == null) {
            return JSendDto.fail("Registration failed");
        }

        session.setAttribute("userId", user.getId());
        return JSendDto.success("Registration successful");
    }

    @GetMapping("/logout")
    public JSendDto logout(HttpSession session) {
        session.removeAttribute("userId");
        return JSendDto.success("Logout successful");
    }

    @GetMapping("/email")
    public JSendDto viewEmail() {
        // FAKE EMAIL SERVICE
        ArrayList<String> emailContent = new ArrayList<>();
        Path path = Paths.get(Constants.EMAIL_PATH);

        if (Files.exists(path)) {
            try {
                emailContent = (ArrayList<String>) Files.readAllLines(path);
            } catch (IOException e) {
                logger.error(e.toString());
            }
        }

        return JSendDto.success(emailContent);
    }

    @PostMapping("/send-password-reset")
    public JSendDto sendPasswordResetEmail(@Valid @RequestBody SendResetPasswordDto sendResetPasswordDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(", "));
            return JSendDto.fail("Validation failed: " + errorMessage);
        }

        String email = sendResetPasswordDto.email();

        UserModel user = userService.findByEmail(email);
        if (user == null) {
            return JSendDto.fail("User not found");
        }

        ResetPasswordToken token = ResetPasswordStorage.getInstance().createResetPasswordToken(user);

        // FAKE EMAIL SERVICE
        if (!user.getUsername().equals("admin")) {
            try (FileWriter fw = new FileWriter(Constants.EMAIL_PATH, true)) {
                fw.write(token.toString() + "\n");
            } catch (IOException e) {
                logger.error(e.toString());
            }
        }

        return JSendDto.success("Password reset email sent");
    }

    @PostMapping("/reset-password")
    public JSendDto resetPassword(@Valid @RequestBody ResetPasswordDto resetPasswordDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(", "));
            return JSendDto.fail("Validation failed: " + errorMessage);
        }

        String email = resetPasswordDto.email();
        String token = resetPasswordDto.token();
        String password = resetPasswordDto.password();

        int userId = ResetPasswordStorage.getInstance().getUserFromResetPasswordToken(
                email,
                token
        );
        UserModel user = userService.findUserById(userId);
        if (user == null) {
            return JSendDto.fail("Wrong email or token.");
        }

        user.setPassword(password);
        if (userService.saveUser(user) == null) {
            return JSendDto.fail("Password reset failed");
        }

        return JSendDto.success("Password reset successful");
    }

}
