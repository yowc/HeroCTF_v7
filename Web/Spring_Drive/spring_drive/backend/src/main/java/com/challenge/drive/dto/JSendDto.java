package com.challenge.drive.dto;

public record JSendDto(String status, String message, Object data) {

    public JSendDto(String status, String message, Object data) {
        this.status = status;
        this.message = message;
        this.data = data;
    }

    public static JSendDto success(Object data) {
        return new JSendDto("success", null, data);
    }

    public static JSendDto success(String message) {
        return new JSendDto("success", message, null);
    }

    public static JSendDto fail(Object data) {
        return new JSendDto("fail", null, data);
    }

    public static JSendDto fail(String message) {
        return new JSendDto("fail", message, null);
    }

    public static JSendDto error(Object data) {
        return new JSendDto("error", null, data);
    }

    public static JSendDto error(String message) {
        return new JSendDto("error", message, null);
    }

}