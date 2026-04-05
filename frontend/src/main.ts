import './lib/i18n';
import './style.css';
import { waitLocale } from 'svelte-i18n';
import App from './App.svelte';

waitLocale().then(() => {
    new App({
        target: document.getElementById('app')!,
    });
});
