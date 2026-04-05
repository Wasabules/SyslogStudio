import { writable } from 'svelte/store';

export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'syslogstudio-theme';

function getInitialTheme(): Theme {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored === 'light' || stored === 'dark') return stored;
    } catch {}
    return 'dark';
}

export const theme = writable<Theme>(getInitialTheme());

theme.subscribe(value => {
    try { localStorage.setItem(STORAGE_KEY, value); } catch {}
    document.documentElement.setAttribute('data-theme', value);
});

export function toggleTheme() {
    theme.update(t => t === 'dark' ? 'light' : 'dark');
}
