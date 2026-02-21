/* BlindBit SSE - Global JS */

function createBlindBitPopup() {
    let activeOverlay = null;

    const ensureRoot = () => {
        let root = document.getElementById('bb-popup-root');
        if (!root) {
            root = document.createElement('div');
            root.id = 'bb-popup-root';
            document.body.appendChild(root);
        }
        return root;
    };

    const closeActive = () => {
        if (!activeOverlay) return;
        activeOverlay.classList.remove('is-open');
        const overlay = activeOverlay;
        activeOverlay = null;
        setTimeout(() => overlay.remove(), 180);
    };

    const open = (config) => {
        closeActive();
        const root = ensureRoot();
        const {
            title = 'Notice',
            message = '',
            tone = 'orange',
            confirmText = 'OK',
            cancelText = '',
            inputConfig = null,
        } = config;

        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'bb-popup-overlay';
            overlay.innerHTML = `
                <div class="bb-popup-card bb-tone-${tone}" role="dialog" aria-modal="true" aria-labelledby="bb-popup-title">
                    <div class="bb-popup-accent"></div>
                    <h3 id="bb-popup-title" class="bb-popup-title"></h3>
                    <p class="bb-popup-message"></p>
                    <div class="bb-popup-body"></div>
                    <div class="bb-popup-actions">
                        <button type="button" class="bb-popup-btn bb-popup-cancel">${cancelText || 'Cancel'}</button>
                        <button type="button" class="bb-popup-btn bb-popup-confirm">${confirmText}</button>
                    </div>
                </div>
            `;

            const titleEl = overlay.querySelector('.bb-popup-title');
            const msgEl = overlay.querySelector('.bb-popup-message');
            const bodyEl = overlay.querySelector('.bb-popup-body');
            const cancelBtn = overlay.querySelector('.bb-popup-cancel');
            const confirmBtn = overlay.querySelector('.bb-popup-confirm');
            const onKeydown = (ev) => {
                if (ev.key === 'Escape') finish(false);
                if (ev.key === 'Enter' && document.activeElement !== cancelBtn) {
                    ev.preventDefault();
                    finish(true);
                }
            };

            titleEl.textContent = title;
            msgEl.textContent = message;
            if (!message) msgEl.style.display = 'none';

            let inputEl = null;
            if (inputConfig) {
                inputEl = document.createElement('input');
                inputEl.type = inputConfig.type || 'text';
                inputEl.className = 'bb-popup-input';
                inputEl.placeholder = inputConfig.placeholder || '';
                inputEl.value = inputConfig.defaultValue || '';
                inputEl.maxLength = inputConfig.maxLength || 200;
                bodyEl.appendChild(inputEl);
            } else {
                bodyEl.style.display = 'none';
            }

            if (!cancelText) {
                cancelBtn.style.display = 'none';
            }

            const finish = (confirmed) => {
                overlay.removeEventListener('click', onOverlayClick);
                document.removeEventListener('keydown', onKeydown);
                closeActive();
                if (!cancelText) {
                    resolve(true);
                    return;
                }
                if (!confirmed) {
                    resolve(inputConfig ? null : false);
                    return;
                }
                resolve(inputConfig ? inputEl.value.trim() : true);
            };

            const onOverlayClick = (event) => {
                if (event.target === overlay) finish(false);
            };

            cancelBtn.addEventListener('click', () => finish(false));
            confirmBtn.addEventListener('click', () => finish(true));
            overlay.addEventListener('click', onOverlayClick);
            document.addEventListener('keydown', onKeydown);

            root.appendChild(overlay);
            activeOverlay = overlay;
            requestAnimationFrame(() => overlay.classList.add('is-open'));
            setTimeout(() => (inputEl || confirmBtn).focus(), 20);
        });
    };

    return {
        alert(message, options = {}) {
            return open({
                title: options.title || 'Notice',
                message,
                tone: options.tone || 'orange',
                confirmText: options.confirmText || 'OK',
                cancelText: '',
            });
        },
        confirm(message, options = {}) {
            return open({
                title: options.title || 'Please Confirm',
                message,
                tone: options.tone || 'orange',
                confirmText: options.confirmText || 'Continue',
                cancelText: options.cancelText || 'Cancel',
            });
        },
        prompt(message, options = {}) {
            return open({
                title: options.title || 'Input Required',
                message,
                tone: options.tone || 'orange',
                confirmText: options.confirmText || 'Save',
                cancelText: options.cancelText || 'Cancel',
                inputConfig: {
                    type: options.type || 'text',
                    placeholder: options.placeholder || '',
                    defaultValue: options.defaultValue || '',
                    maxLength: options.maxLength || 200,
                },
            });
        },
    };
}

window.BlindBitPopup = createBlindBitPopup();

// Auto-dismiss alerts after 4 seconds
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.alert').forEach(a => {
        setTimeout(() => {
            a.style.opacity = '0';
            a.style.transform = 'translateY(-10px)';
            setTimeout(() => a.remove(), 300);
        }, 4000);
    });

    const logoutForm = document.getElementById('logout-form');
    if (logoutForm) {
        logoutForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const shouldSignOut = await window.BlindBitPopup.confirm(
                'Are you sure you want to sign out?',
                { title: 'Sign Out', confirmText: 'Sign out' }
            );
            if (shouldSignOut) logoutForm.submit();
        });
    }

    const recoverySavedLink = document.getElementById('recovery-saved-link');
    if (recoverySavedLink) {
        recoverySavedLink.addEventListener('click', async (event) => {
            event.preventDefault();
            const confirmed = await window.BlindBitPopup.confirm(
                'Please confirm: have you downloaded and safely stored your recovery codes? These codes may be required to regain access.'
            );
            if (confirmed) {
                window.location.href = recoverySavedLink.href;
            }
        });
    }
});
