// AUTH
export interface AuthState {
    isAuthenticated: boolean;
    isInitialized: boolean;
    user: UserModel | null;
}

// MODELS
export interface UserModel {
    id: number;
    username: string;
    email: string;
    password: string;
    creationDate: Date;
}

export interface FileModel {
    id: number;
    filename:  string;
    filePath: string;
    fileSize: number;
}

// API
export interface APIResponse {
    status: string;
    message: string | null;
    data: object | null;
}

export interface LoginRequest {
    username: string;
    password: string;
}

export interface RegisterRequest {
    username: string;
    email: string;
    password: string;
    confirmPassword: string;
}

export interface ResetPasswordRequest {
    email: string;
    token: string;
    password: string;
}

export interface SendResetPasswordRequest {
    email: string;
}

export interface RemoteUploadRequest {
    url: string;
    filename: string;
    httpMethod: string;
}

export interface DownloadFileRequest {
    fileId: number,
}

export interface RemoveFileRequest {
    fileId: number;
}

export interface DownloadFileResponse {
    base64: string,
}