package com.challenge.drive.service;

import com.challenge.drive.model.FileModel;
import com.challenge.drive.repository.FileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FileService {

    @Autowired
    private FileRepository fileRepository;

    public FileModel findById(int fileId) {
        return fileRepository.findById(fileId);
    }

    public List<FileModel> findByUserId(int userId) {
        return fileRepository.findByUserId(userId);
    }

    public void delete(FileModel fileModel) {
        fileRepository.delete(fileModel);
    }

    public void saveFile(FileModel fileModel) {
        ClamAVService.getInstance().addToScan(fileModel.getFilePath());
        fileRepository.save(fileModel);
    }

}
