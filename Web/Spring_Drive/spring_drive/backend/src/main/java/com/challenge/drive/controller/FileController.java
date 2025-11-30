package com.challenge.drive.controller;

import com.challenge.drive.config.Constants;
import com.challenge.drive.dto.*;
import com.challenge.drive.model.FileModel;
import com.challenge.drive.service.FileService;
import com.challenge.drive.service.UserService;
import jakarta.servlet.http.HttpSession;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.UUID;

@RestController
@RequestMapping("/file")
public class FileController {

    private static final Logger logger = LoggerFactory.getLogger(FileController.class);

    @Autowired
    private FileService fileService;

    @Autowired
    private UserService userService;

    @GetMapping("/")
    public JSendDto listFiles(HttpSession session) {
        int userId = (int) session.getAttribute("userId");

        try {
            List<FileModel> files = fileService.findByUserId(userId);
            return JSendDto.success(files);
        } catch (Exception e) {
            logger.error("An exception occurred while listing files", e);
            return JSendDto.error("An exception occurred while listing files");
        }
    }

    @PostMapping("/download")
    public JSendDto downloadFile(HttpSession session, @RequestBody DownloadFileDto downloadFileDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(", "));
            return JSendDto.fail("Validation failed: " + errorMessage);
        }
        int userId = (int) session.getAttribute("userId");
        int fileId = downloadFileDto.fileId();

        FileModel fileModel = fileService.findById(fileId);
        if (fileModel == null) {
            return JSendDto.error("Unable to find the file");
        }

        if (fileModel.getUserId() != userId) {
            return JSendDto.error("Unable to access the file");
        }

        try {
            Path filePath = Paths.get(fileModel.getFilePath());
            byte[] fileContent = Files.readAllBytes(filePath);
            String fileContentBase64 = Base64.getEncoder().encodeToString(fileContent);
            DownloadFileOutputDto downloadFileOutputDto = new DownloadFileOutputDto(fileContentBase64);
            return JSendDto.success(downloadFileOutputDto);
        } catch (Exception e) {
            logger.error("An exception occurred while downloading the file", e);
            return JSendDto.error("An exception occurred while downloading the file");
        }
    }

    @DeleteMapping("/remove")
    public JSendDto removeFile(HttpSession session, @RequestBody RemoveFileDto removeFileDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(", "));
            return JSendDto.fail("Validation failed: " + errorMessage);
        }
        int userId = (int) session.getAttribute("userId");
        int fileId = removeFileDto.fileId();

        FileModel fileModel = fileService.findById(fileId);
        if (fileModel == null) {
            return JSendDto.error("Unable to find the file");
        }

        if (fileModel.getUserId() != userId) {
            return JSendDto.error("Unable to access the file");
        }

        String filePathStr = fileModel.getFilePath();
        Path filePath = Paths.get(filePathStr);
        try {
            Files.deleteIfExists(filePath);
        } catch (Exception e) {
            logger.error("An exception occurred while removing the file", e);
            return JSendDto.error("An exception occurred while removing the file");
        }

        fileService.delete(fileModel);
        return JSendDto.success("File successfully removed");
    }

    @PostMapping("/upload")
    public JSendDto uploadFile(HttpSession session, @RequestBody MultipartFile file) {
        if (file.isEmpty()) {
            return JSendDto.fail("Please select a file to upload");
        }
        int userId = (int) session.getAttribute("userId");

        try {
            Path uploadPath = Paths.get(Constants.UPLOAD_DIR);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            String fileName = UUID.randomUUID().toString();
            Path filePath = uploadPath.resolve(fileName);
            Files.write(filePath, file.getBytes());

            FileModel fileModel = new FileModel();
            fileModel.setFilePath(filePath.toUri().getPath());
            fileModel.setFileSize((int) file.getSize());
            fileModel.setFilename(fileName);
            fileModel.setUserId(userId);
            fileService.saveFile(fileModel);

            return JSendDto.success("File uploaded successfully");
        } catch (Exception e) {
            return JSendDto.error("An error occurred while uploading the file");
        }
    }

    @PostMapping("/remote-upload")
    public JSendDto remoteUploadFile(HttpSession session, @RequestBody RemoteUploadDto remoteUploadDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(", "));
            return JSendDto.fail("Validation failed: " + errorMessage);
        }
        int userId = (int) session.getAttribute("userId");
        if (userId != 1) {
            return JSendDto.fail("You must be admin to access this feature.");
        }

        String method = remoteUploadDto.httpMethod();
        String remoteUrl = remoteUploadDto.url();

        try {
            Path uploadPath = Paths.get(Constants.UPLOAD_DIR);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url(remoteUrl)
                    .method(method, null)
                    .build();

            String fileName = UUID.randomUUID().toString();
            Path filePath = uploadPath.resolve(fileName);

            Response response = client.newCall(request).execute();
            if (!response.isSuccessful()) {
                return JSendDto.error("Failed to request the file");
            }

            okhttp3.ResponseBody responseBody = response.body();
            if (responseBody == null) {
                return JSendDto.error("Failed to download the file");
            }

            Files.copy(responseBody.byteStream(), filePath, StandardCopyOption.REPLACE_EXISTING);

            FileModel fileModel = new FileModel();
            fileModel.setFilePath(filePath.toUri().getPath());
            fileModel.setFileSize((int) responseBody.contentLength());
            fileModel.setFilename(fileName);
            fileModel.setUserId(userId);
            fileService.saveFile(fileModel);

            return JSendDto.success("File uploaded successfully");
        } catch (Exception e) {
            return JSendDto.error("An exception occurred while downloading the file");
        }
    }

}