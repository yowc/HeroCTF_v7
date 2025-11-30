import { writable } from 'svelte/store';
import type {UserModel, AuthState, APIResponse} from '$lib/types';
import {handleProfile} from "$lib/api";


function createAuthStore() {
    const defaultState = {
        isAuthenticated: false,
        user: null,
        isInitialized: false
    };

    const { subscribe, set, update } = writable<AuthState>(defaultState);

    return {
        subscribe,
        setUser: (user: UserModel | null) => {
            set({
                isAuthenticated: !!user,
                isInitialized: true,
                user,
            });
        },
        clearSession: () => {
            set(defaultState);
        },
        isInitialized: () => {
            let state: AuthState = defaultState;
            subscribe(value => state = value)();
            return state.isInitialized;
        },
        isAuthenticated: () => {
            let state: AuthState = defaultState;
            subscribe(value => state = value)();
            return state.isInitialized;
        },
        getUser: () => {
            let state: AuthState = defaultState;
            subscribe(value => state = value)();
            return state.user;
        }
    };
}

export const authStore = createAuthStore();


export async function checkAuthStatus(): Promise<void> {
    try {
        if (!authStore.isInitialized()) {
            const resp: APIResponse = await handleProfile();
            if (resp.status === 'fail') {
                authStore.setUser(null);
            } else {
                authStore.setUser(resp.data as UserModel);
            }
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        authStore.setUser(null);
    }
}