/**
 * Puts text on the clipboard, or says it could not.
 *
 * The async clipboard API needs a secure context and a permission that a
 * webview does not always grant. The old selection-based path still works
 * everywhere, so it stands behind the new one rather than the copy simply
 * doing nothing — a menu item that silently fails is worse than no menu item.
 */
export async function copyText(text: string): Promise<boolean> {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch { /* fall through */ }

    try {
        const area = document.createElement('textarea');
        area.value = text;
        // Off-screen but focusable: a hidden element cannot be selected, and
        // scrolling the page to a visible one would move the list underneath.
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.top = '0';
        area.style.left = '-9999px';
        document.body.appendChild(area);
        area.select();
        const ok = document.execCommand('copy');
        area.remove();
        return ok;
    } catch {
        return false;
    }
}
