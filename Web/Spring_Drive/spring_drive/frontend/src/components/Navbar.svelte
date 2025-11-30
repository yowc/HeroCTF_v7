<script lang="ts">
    import { goto } from '$app/navigation';
    import { authStore } from "$lib/authStore";
    import {onMount} from "svelte";

    onMount(() => {
        if (authStore.isInitialized() && !authStore.isAuthenticated()) {
            goto('/auth');
        }
    })

    const login = () => goto('/auth');
    const logout = () => {
        authStore.setUser(null);
        login();
    };
</script>


<nav class="desktop-navbar">
    <div class="navbar-container">
        <div class="navbar-brand">
            <a href="/" class="logo">Drive</a>
        </div>

        <div class="navbar-actions">
            {#if $authStore.isAuthenticated}
                <div class="user-info">
                    <span class="username">{$authStore.user?.username}</span>
                    <button on:click={logout} class="btn btn-outline">Logout</button>
                </div>
            {:else}
                <button on:click={login} class="btn btn-outline">Login or Sign Up</button>
            {/if}
        </div>
    </div>
</nav>

<style>
    .desktop-navbar {
        background-color: white;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        padding: 0.5rem 1rem;
        position: sticky;
        top: 0;
        z-index: 1000;
    }

    .navbar-container {
        max-width: 1200px;
        margin: 0 auto;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .navbar-brand {
        display: flex;
        align-items: center;
    }

    .logo {
        font-size: 1.5rem;
        font-weight: bold;
        color: #333;
        text-decoration: none;
    }

    .navbar-actions {
        display: flex;
        align-items: center;
        gap: 1rem;
    }

    .user-info {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }

    .username {
        font-weight: 500;
        color: #333;
    }

    /* Button styles */
    .btn {
        padding: 0.5rem 1rem;
        border-radius: 4px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s;
        text-decoration: none;
        display: inline-block;
        text-align: center;
        border: 1px solid transparent;
    }

    .btn-outline {
        background-color: transparent;
        color: #007bff;
        border-color: #007bff;
    }

    .btn-outline:hover {
        background-color: rgba(0, 123, 255, 0.1);
    }
</style>
