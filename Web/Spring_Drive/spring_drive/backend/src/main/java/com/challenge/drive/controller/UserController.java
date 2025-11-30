package com.challenge.drive.controller;

import com.challenge.drive.dto.JSendDto;
import com.challenge.drive.dto.UserOutputDto;
import com.challenge.drive.model.UserModel;
import com.challenge.drive.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/profile")
    public JSendDto profile(HttpSession session) {
        int userId = (int) session.getAttribute("userId");

        UserModel user = userService.findUserById(userId);
        if (user == null) {
            return JSendDto.fail("User not found");
        }

        UserOutputDto userOutput = new UserOutputDto(user.getId(), user.getUsername(), user.getEmail());
        return JSendDto.success(userOutput);
    }

}
