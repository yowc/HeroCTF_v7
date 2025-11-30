<script lang="ts">
    import {goto} from '$app/navigation';
    import {handleLogin, handleRegister} from '$lib/api';
    import type {APIResponse} from '$lib/types';
    import {authStore} from "$lib/authStore";

    let isLogin: boolean = true;
    let error: string = '';
    let isLoading: boolean = false;
    let showPassword: boolean = false;
    let showConfirmPassword: boolean = false;

    let username: string = '';
    let email: string = '';
    let password: string = '';
    let confirmPassword: string = '';

    const toggleForm = (): void => {
        isLogin = !isLogin;
        error = '';

        username = '';
        email = '';
        password = '';
        confirmPassword = '';
    };

    const submitForm = async (): Promise<void> => {
        error = '';
        isLoading = true;
        try {
            let resp: APIResponse;
            if (isLogin) {
                resp = await handleLogin(username, password);
            } else {
                resp = await handleRegister(username, email, password, confirmPassword);
            }

            if (resp.status === 'success') {
                authStore.clearSession();
                await goto('/');
            } else {
                error = resp.message ? resp.message : 'An unknown error occurred';
            }
        } catch (err: unknown) {
            error = err instanceof Error ? err.message : 'An unknown error occurred';
        } finally {
            isLoading = false;
        }
    };
</script>

<div class="auth-container">
    <h1>{isLogin ? 'Login' : 'Register'}</h1>

    {#if error}
        <div class="error-message">
            {error}
        </div>
    {/if}

    <form on:submit|preventDefault={submitForm} class="auth-form">
        <div class="form-group">
            <label for="username">Username:</label>
            <input
                    type="text"
                    id="username"
                    bind:value={username}
                    class="form-input"
            />
        </div>

        {#if !isLogin}
            <div class="form-group">
                <label for="email">Email:</label>
                <input
                        type="email"
                        id="email"
                        bind:value={email}
                        required
                        class="form-input"
                />
            </div>
        {/if}

        <div class="form-group">
            <label for="password">Password:</label>
            <div class="password-input-container">
                <input
                        type={showPassword ? 'text' : 'password'}
                        id="password"
                        bind:value={password}
                        required
                        class="form-input password-input"
                />
                <button
                        type="button"
                        on:click={() => showPassword = !showPassword}
                        class="password-toggle"
                >
                    {showPassword ? 'Hide' : 'Show'}
                </button>
            </div>
            {#if !isLogin}
                <p class="password-hint">Password must be at least 8 characters long</p>
            {/if}
        </div>

        {#if !isLogin}
            <div class="form-group">
                <label for="confirmPassword">Confirm Password:</label>
                <div class="password-input-container">
                    <input
                            type={showConfirmPassword ? 'text' : 'password'}
                            id="confirmPassword"
                            bind:value={confirmPassword}
                            required
                            class="form-input password-input"
                    />
                    <button
                            type="button"
                            on:click={() => showConfirmPassword = !showConfirmPassword}
                            class="password-toggle"
                    >
                        {showConfirmPassword ? 'Hide' : 'Show'}
                    </button>
                </div>
            </div>
        {/if}

        <button type="submit" disabled={isLoading} class="submit-button">
            {#if isLoading}
                {#if isLogin}
                    Logging in...
                {:else}
                    Registering...
                {/if}
            {:else}
                {#if isLogin}
                    Login
                {:else}
                    Register
                {/if}
            {/if}
        </button>
    </form>

    <div class="form-toggle">
        {#if isLogin}
            Don't have an account?
            <button on:click|preventDefault={toggleForm} class="toggle-button">Register here</button>
        {:else}
            Already have an account?
            <button on:click|preventDefault={toggleForm} class="toggle-button">Login here</button>
        {/if}
    </div>
</div>

<style>
    .auth-container {
        max-width: 400px;
        margin: 0 auto;
        padding: 2rem;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        background-color: white;
    }

    h1 {
        text-align: center;
        margin-bottom: 1.5rem;
        color: #333;
    }

    .error-message {
        color: #d32f2f;
        background-color: #ffebee;
        padding: 0.75rem;
        border-radius: 4px;
        margin-bottom: 1rem;
        text-align: center;
    }

    .auth-form {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }

    .form-group {
        margin-bottom: 1rem;
    }

    label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
        color: #555;
    }

    .form-input {
        width: 100%;
        padding: 0.75rem;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 1rem;
        transition: border-color 0.3s;
    }

    .form-input:focus {
        outline: none;
        border-color: #007bff;
        box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
    }

    .password-input-container {
        position: relative;
    }

    .password-input {
        padding-right: 3rem;
    }

    .password-toggle {
        position: absolute;
        right: 0;
        top: 0;
        height: 100%;
        background: none;
        border: none;
        color: #007bff;
        cursor: pointer;
        padding: 0 0.75rem;
        display: flex;
        align-items: center;
    }

    .password-hint {
        font-size: 0.8rem;
        color: #666;
        margin-top: 0.25rem;
    }

    .submit-button {
        padding: 0.75rem;
        background-color: #007bff;
        color: white;
        border: none;
        border-radius: 4px;
        font-size: 1rem;
        font-weight: 500;
        cursor: pointer;
        transition: background-color 0.3s;
        margin-top: 0.5rem;
    }

    .submit-button:hover:not(:disabled) {
        background-color: #0056b3;
    }

    .submit-button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
    }

    .form-toggle {
        margin-top: 1rem;
        text-align: center;
        color: #666;
    }

    .toggle-button {
        background: none;
        border: none;
        color: #007bff;
        cursor: pointer;
        font-weight: 500;
        padding: 0;
        margin-left: 0.25rem;
        text-decoration: underline;
    }

    .toggle-button:hover {
        text-decoration: none;
    }
</style>
