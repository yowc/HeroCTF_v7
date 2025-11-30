package com.challenge.drive.service;

import com.challenge.drive.model.UserModel;
import com.challenge.drive.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public UserModel findUserById(int id) {
        return userRepository.findById(id);
    }

    public UserModel findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public UserModel findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public UserModel findByUsernameAndPassword(String username, String password) {
        return userRepository.findByUsernameAndPassword(username, password);
    }

    public UserModel saveUser(UserModel user) {
        return userRepository.save(user);
    }

}
