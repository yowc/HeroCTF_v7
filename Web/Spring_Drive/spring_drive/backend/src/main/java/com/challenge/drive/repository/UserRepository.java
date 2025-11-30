package com.challenge.drive.repository;

import com.challenge.drive.model.UserModel;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserModel, Integer> {
    UserModel findById(int id);

    UserModel findByUsername(String username);

    UserModel findByEmail(String email);

    UserModel findByUsernameAndPassword(String username, String password);
}