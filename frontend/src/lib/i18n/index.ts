import { addMessages, register, init, getLocaleFromNavigator, locale } from 'svelte-i18n';
import { derived } from 'svelte/store';
import en from './en.json';

const STORAGE_KEY = 'syslogstudio-locale';

export const SUPPORTED_LOCALES = [
    { code: 'en', label: 'English' },
    { code: 'fr', label: 'Français' },
    { code: 'de', label: 'Deutsch' },
    { code: 'es', label: 'Español' },
    { code: 'pt', label: 'Português' },
    { code: 'it', label: 'Italiano' },
    { code: 'ja', label: '日本語' },
    { code: 'zh', label: '中文' },
];

const LOCALE_CODES = SUPPORTED_LOCALES.map(l => l.code);

function getInitialLocale(): string {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored && LOCALE_CODES.includes(stored)) return stored;
    } catch {}
    const nav = getLocaleFromNavigator() || 'en';
    const base = nav.split('-')[0];
    return LOCALE_CODES.includes(base) ? base : 'en';
}

// Load English synchronously (fallback always available)
addMessages('en', en);

// All other languages loaded lazily
register('fr', () => import('./fr.json'));
register('de', () => import('./de.json'));
register('es', () => import('./es.json'));
register('pt', () => import('./pt.json'));
register('it', () => import('./it.json'));
register('ja', () => import('./ja.json'));
register('zh', () => import('./zh.json'));

init({
    fallbackLocale: 'en',
    initialLocale: getInitialLocale(),
});

export const currentLocale = locale;
export const appLocale = derived(locale, ($locale) => $locale || 'en');

export function setLocale(lang: string) {
    locale.set(lang);
    try { localStorage.setItem(STORAGE_KEY, lang); } catch {}
}
