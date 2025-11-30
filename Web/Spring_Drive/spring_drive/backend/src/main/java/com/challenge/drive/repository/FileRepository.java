package com.challenge.drive.repository;

import com.challenge.drive.model.FileModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FileRepository extends JpaRepository<FileModel, Integer> {
    FileModel findById(int fileId);

    List<FileModel> findByUserId(int userId);
}