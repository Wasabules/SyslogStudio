import { writable } from 'svelte/store';

export interface Toast {
    id: number;
    type: 'success' | 'error' | 'info';
    message: string;
}

let nextId = 0;

export const toasts = writable<Toast[]>([]);

function addToast(type: Toast['type'], message: string, duration = 4000) {
    const id = nextId++;
    toasts.update(t => [...t, { id, type, message }]);
    if (duration > 0) {
        setTimeout(() => dismissToast(id), duration);
    }
}

export function dismissToast(id: number) {
    toasts.update(t => t.filter(toast => toast.id !== id));
}

export function toastSuccess(message: string) {
    addToast('success', message);
}

export function toastError(message: string) {
    addToast('error', message, 6000);
}

export function toastInfo(message: string) {
    addToast('info', message);
}
