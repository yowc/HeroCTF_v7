import type {
    APIResponse, DownloadFileRequest,
    LoginRequest,
    RegisterRequest, RemoteUploadRequest, RemoveFileRequest,
    ResetPasswordRequest,
    SendResetPasswordRequest
} from "$lib/types";
import {validateEmail, validatePassword} from "$lib/utils";
import {API_BASE_URL} from "$lib/constants";


const errorMessage = function (message: string): APIResponse {
    return {
        status: "error",
        message: message,
        data: null
    } as APIResponse;
}

export const handleProfile = async (): Promise<APIResponse> => {
    const response = await fetch(`${API_BASE_URL}/user/profile`, {
        method: 'GET',
        credentials: 'include',
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
}

export const handleLogin = async (username: string, password: string): Promise<APIResponse> => {
    if (!username || !password) {
        return errorMessage('Username and password are required.');
    }

    const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({username, password} as LoginRequest),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};

export const handleRegister = async (
    username: string,
    email: string,
    password: string,
    confirmPassword: string
): Promise<APIResponse> => {
    if (!username || !email || !password || !confirmPassword) {
        return errorMessage('Username, email, password, and confirm password are required.');
    }

    if (!validateEmail(email)) {
        return errorMessage('Please enter a valid email address.');
    }

    if (!validatePassword(password)) {
        return errorMessage('Password must be at least 8 characters long.');
    }

    if (password !== confirmPassword) {
        return errorMessage('Passwords do not match.');
    }

    const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({username, email, password, confirmPassword} as RegisterRequest),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};

export const handleListFiles = async (): Promise<APIResponse> => {
    const response = await fetch(`${API_BASE_URL}/file/`, {
        method: 'GET'
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};

export const handleSendResetPassword = async (
    email: string,
): Promise<APIResponse> => {
    if (!email) {
        return errorMessage('Email is required.');
    }

    if (!validateEmail(email)) {
        return errorMessage('Please enter a valid email address.');
    }


    const response = await fetch(`${API_BASE_URL}/auth/send-reset-password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({email} as SendResetPasswordRequest),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};

export const handleResetPassword = async (
    email: string,
    token: string,
    password: string,
): Promise<APIResponse> => {
    if (!email || !token || !password) {
        return errorMessage('Email, token and password are required.')
    }

    if (!validateEmail(email)) {
        return errorMessage('Please enter a valid email address.');
    }

    if (!validatePassword(password)) {
        return errorMessage('Password must be at least 8 characters long.')
    }

    const response = await fetch(`${API_BASE_URL}/auth/reset-password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({email, token, password} as ResetPasswordRequest),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};

export const handleRemoteUploadFile = async (
    url: string,
    filename: string,
    httpMethod: string,
): Promise<APIResponse> => {
    if (!url || !filename) {
        return errorMessage('URL and filename are required.')
    }

    const response = await fetch(`${API_BASE_URL}/file/remote-upload`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({url, filename, httpMethod} as RemoteUploadRequest),
        credentials: 'include',
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};

export const handleDownloadFile = async (
    fileId: number
): Promise<APIResponse> => {
    if (!fileId) {
        return errorMessage('File ID is required.');
    }

    const response = await fetch(`${API_BASE_URL}/file/download`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({fileId} as DownloadFileRequest),
        credentials: 'include',
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};

export const handleUploadFile = async (
    file: File
): Promise<APIResponse> => {
    if (!file) {
        return errorMessage('File is required.');
    }

    const formData = new FormData();
    formData.append("file", file)

    const response = await fetch(`${API_BASE_URL}/file/upload`, {
        method: 'POST',
        body: formData,
        credentials: 'include',
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};

export const handleRemoveFile = async (
    fileId: number
): Promise<APIResponse> => {
    if (!fileId) {
        return errorMessage('File ID is required.');
    }

    const response = await fetch(`${API_BASE_URL}/file/remove`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({fileId} as RemoveFileRequest),
        credentials: 'include',
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return errorMessage(errorData.message || 'Request failed.');
    }

    return await response.json() as APIResponse;
};