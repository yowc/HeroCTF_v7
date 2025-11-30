<script lang="ts">
    import {authStore, checkAuthStatus} from "$lib/authStore";
    import {onMount} from "svelte";
    import {
        handleListFiles,
        handleUploadFile,
        handleRemoveFile,
        handleRemoteUploadFile,
        handleDownloadFile
    } from "$lib/api";
    import type {APIResponse, DownloadFileResponse, FileModel} from "$lib/types";

    let files: FileModel[] = [];
    let loading = false;
    let errorMsg = "";

    // Remote upload modal state
    let showRemoteModal = false;
    let remoteUrl = "";
    let remoteMethod = "GET";
    let remoteFilename = "";

    onMount(async () => {
        await checkAuthStatus();
        if (authStore.isInitialized() && authStore.isAuthenticated()) {
            await fetchFiles();
        }
    });

    async function fetchFiles() {
        loading = true;
        errorMsg = "";
        const resp: APIResponse = await handleListFiles();
        if (resp.status === "success") {
            files = resp.data as FileModel[];
        } else {
            errorMsg = resp.message || "Failed to load files.";
        }
        loading = false;
    }

    async function uploadFile(e: Event) {
        const target = e.target as HTMLInputElement;
        const file = target.files?.[0];
        if (!file) return;

        errorMsg = "";
        const resp: APIResponse = await handleUploadFile(file);
        if (resp.status === "success") {
            await fetchFiles();
        } else {
            errorMsg = resp.message || "File upload failed.";
        }
    }

    async function uploadRemoteFile() {
        errorMsg = "";
        const resp: APIResponse = await handleRemoteUploadFile(remoteUrl, remoteFilename, remoteMethod);
        if (resp.status === "success") {
            await fetchFiles();
            closeModal();
        } else {
            errorMsg = resp.message || "Remote file upload failed.";
        }
    }

    async function downloadFile(file: FileModel) {
        errorMsg = "";
        const resp: APIResponse = await handleDownloadFile(file.id);
        if (resp.status === "success" && resp.data !== null) {
            const blob = new Blob([atob((resp.data as DownloadFileResponse).base64 || "")], { type: "application/octet-stream" });
            const url = window.URL.createObjectURL(blob);

            const a = document.createElement("a");
            a.href = url;
            a.download = file.filename || `file_${file.id}`;
            document.body.appendChild(a);
            a.click();

            a.remove();
            window.URL.revokeObjectURL(url);
        } else {
            errorMsg = resp.message || "Failed to download file.";
        }
    }

    async function removeFile(file: FileModel) {
        errorMsg = "";
        const resp: APIResponse = await handleRemoveFile(file.id);
        if (resp.status === "success") {
            files = files.filter(f => f.id !== file.id);
        } else {
            errorMsg = resp.message || "Failed to remove file.";
        }
    }

    function closeModal() {
        showRemoteModal = false;
        remoteUrl = "";
        remoteMethod = "GET";
        remoteFilename = "";
    }

    function formatSize(size: number): string {
        if (size < 1024) return `${size} B`;
        if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
        return `${(size / (1024 * 1024)).toFixed(1)} MB`;
    }
</script>

<section>
    {#if $authStore.isAuthenticated}
        <div class="upload-section">
            <label class="upload-btn">
                Choose File
                <input type="file" on:change={uploadFile}/>
            </label>
            <button class="btn btn-remote" on:click={() => showRemoteModal = true}>
                Upload Remote File
            </button>
        </div>

        <div class="files-section">
            {#if errorMsg}
                <p class="error">{errorMsg}</p>
            {/if}
            {#if loading}
                <p>Loading...</p>
            {:else if files.length === 0}
                <p>No files available.</p>
            {:else}
                <table>
                    <thead>
                    <tr>
                        <th>Filename</th>
                        <th>Size</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {#each files as file}
                        <tr>
                            <td>{file.filename}</td>
                            <td>{formatSize(file.fileSize)}</td>
                            <td>
                                <button class="btn btn-primary" on:click={() => downloadFile(file)} disabled={loading}>
                                    Download
                                </button>
                                <button class="btn btn-danger" on:click={() => removeFile(file)} disabled={loading}>
                                    Remove
                                </button>
                            </td>
                        </tr>
                    {/each}
                    </tbody>
                </table>
            {/if}
        </div>

        {#if showRemoteModal}
            <button class="modal-overlay" on:click={closeModal}>Close</button>
            <div class="modal">
                <h3>Upload Remote File</h3>
                <label>
                    Remote URL:
                    <input type="text" bind:value={remoteUrl} placeholder="https://example.com/file.zip"/>
                </label>
                <label>
                    HTTP Method:
                    <select bind:value={remoteMethod}>
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                    </select>
                </label>
                <label>
                    Filename:
                    <input type="text" bind:value={remoteFilename} placeholder="myfile.zip"/>
                </label>
                <div class="modal-actions">
                    <button class="btn btn-primary" on:click={uploadRemoteFile}>Upload</button>
                    <button class="btn btn-secondary" on:click={closeModal}>Cancel</button>
                </div>
            </div>
        {/if}
    {:else}
        <p>Please log in to manage files.</p>
    {/if}
</section>

<style>
    section {
        margin-top: 50px;
        margin-left: 10%;
        margin-right: 10%;
    }

    .upload-section {
        margin-bottom: 2rem;
        text-align: center;
    }

    .upload-section input[type="file"] {
        display: none;
    }

    .upload-btn {
        display: inline-block;
        padding: 0.6rem 1.2rem;
        background: #3498db;
        color: white;
        border-radius: 6px;
        font-size: 1rem;
        font-weight: 500;
        cursor: pointer;
        transition: background 0.2s ease;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        margin-right: 1rem;
    }

    .upload-btn:hover {
        background: #2980b9;
    }

    .btn {
        padding: 0.5rem 1rem;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        font-size: 0.9rem;
        transition: background 0.2s ease;
    }

    .btn-primary {
        background: #27ae60;
        color: white;
    }

    .btn-primary:hover {
        background: #1e8449;
    }

    .btn-secondary {
        background: #bdc3c7;
        color: #2c3e50;
    }

    .btn-secondary:hover {
        background: #95a5a6;
    }

    .btn-remote {
        background: #8e44ad;
        color: white;
        display: inline-block;
        padding: 0.6rem 1.2rem;
        border-radius: 6px;
        font-size: 1rem;
        font-weight: 500;
        cursor: pointer;
        transition: background 0.2s ease;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        margin-right: 1rem;
    }

    .btn-remote:hover {
        background: #6c3483;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 1rem;
        background: #fff;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
    }

    th, td {
        padding: 0.75rem 1rem;
        text-align: left;
        border-bottom: 1px solid #eee;
    }

    th {
        background: #f8f9fa;
        font-weight: 600;
    }

    tr:hover {
        background: #f5f5f5;
    }

    .btn-danger {
        background: #e74c3c;
        color: white;
    }

    .btn-danger:hover {
        background: #c0392b;
    }

    .btn[disabled] {
        opacity: 0.6;
        cursor: not-allowed;
    }

    .error {
        color: #e74c3c;
        font-weight: 500;
    }

    /* Modal styles */
    .modal-overlay {
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,0.5);
        z-index: 99;
    }

    .modal {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        padding: 2rem;
        border-radius: 8px;
        width: 400px;
        max-width: 90%;
        z-index: 100;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }

    .modal h3 {
        margin-bottom: 1rem;
    }

    .modal label {
        display: block;
        margin-bottom: 0.8rem;
        font-size: 0.9rem;
    }

    .modal input, .modal select {
        width: 100%;
        padding: 0.4rem;
        margin-top: 0.3rem;
        border: 1px solid #ccc;
        border-radius: 4px;
    }

    .modal-actions {
        margin-top: 1rem;
        display: flex;
        justify-content: flex-end;
        gap: 0.5rem;
    }
</style>
