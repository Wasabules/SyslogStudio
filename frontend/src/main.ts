import './lib/i18n';
import './style.css';
import { waitLocale } from 'svelte-i18n';
import { mount } from 'svelte';
import App from './App.svelte';

// Svelte 5 refuses `new App({ target })` (component_api_invalid_new): a
// component is no longer a class. mount() is the replacement.
waitLocale().then(() => {
    mount(App, {
        target: document.getElementById('app')!,
    });
});
