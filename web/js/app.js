/**
 * Kipuka EST Server — Admin Dashboard
 *
 * Single-file vanilla JavaScript application for managing the Kipuka EST
 * server via its admin API.  No framework dependencies — PatternFly 5 CSS
 * only.
 */

'use strict';

// ── API Client ─────────────────────────────────────────────────────────

const API = {
    get token() {
        return sessionStorage.getItem('kipuka_token');
    },

    set token(val) {
        if (val) {
            sessionStorage.setItem('kipuka_token', val);
        } else {
            sessionStorage.removeItem('kipuka_token');
        }
    },

    async request(method, path, body) {
        const opts = {
            method,
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'Accept': 'application/json',
            },
        };
        if (body !== undefined) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const resp = await fetch(path, opts);
        if (resp.status === 204) return null;
        if (resp.status === 401) {
            App.logout();
            throw new Error('Session expired');
        }
        const data = await resp.json().catch(() => null);
        if (!resp.ok) {
            const msg = data?.detail || data?.error || resp.statusText;
            throw new Error(msg);
        }
        return data;
    },

    get(path) { return this.request('GET', path); },
    post(path, body) { return this.request('POST', path, body); },
    del(path) { return this.request('DELETE', path); },
};

// ── Utilities ──────────────────────────────────────────────────────────

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function escHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

function fmtTime(iso) {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleString();
    } catch {
        return iso;
    }
}

function fmtUptime(secs) {
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    parts.push(`${s}s`);
    return parts.join(' ');
}

function statusColor(status) {
    const s = (status || '').toLowerCase();
    if (s === 'healthy' || s === 'valid' || s === 'active') return 'green';
    if (s === 'degraded' || s === 'expired') return 'orange';
    if (s === 'unhealthy' || s === 'revoked') return 'red';
    return 'grey';
}

function labelHtml(text, color) {
    const pfColor = {
        green: 'pf-m-green',
        orange: 'pf-m-orange',
        red: 'pf-m-red',
        grey: '',
        blue: 'pf-m-blue',
        yellow: 'pf-m-gold',
    }[color] || '';
    return `<span class="pf-v5-c-label pf-m-compact ${pfColor}">
        <span class="pf-v5-c-label__content">${escHtml(text)}</span>
    </span>`;
}

function spinnerHtml(size) {
    const szClass = size === 'lg' ? 'pf-m-lg' : 'pf-m-md';
    return `<div class="kipuka-loading">
        <span class="pf-v5-c-spinner ${szClass}" role="progressbar" aria-label="Loading">
            <span class="pf-v5-c-spinner__clipper"></span>
            <span class="pf-v5-c-spinner__lead-ball"></span>
            <span class="pf-v5-c-spinner__tail-ball"></span>
        </span>
    </div>`;
}

function alertHtml(message, type) {
    const cls = type === 'danger' ? 'pf-m-danger' : type === 'success' ? 'pf-m-success' : 'pf-m-warning';
    return `<div class="pf-v5-c-alert ${cls} pf-m-inline kipuka-alert-banner" aria-label="Alert">
        <div class="pf-v5-c-alert__icon">
            <svg class="pf-v5-svg" viewBox="0 0 512 512" width="16" height="16">
                <path d="M256 0C114.6 0 0 114.6 0 256s114.6 256 256 256 256-114.6 256-256S397.4 0 256 0zm-21.4 383.5c0 11.8 9.6 21.4 21.4 21.4s21.4-9.6 21.4-21.4v-21.4c0-11.8-9.6-21.4-21.4-21.4s-21.4 9.6-21.4 21.4v21.4zm0-106.7V149.3c0-11.8 9.6-21.4 21.4-21.4s21.4 9.6 21.4 21.4v127.5c0 11.8-9.6 21.4-21.4 21.4s-21.4-9.6-21.4-21.4z" fill="currentColor"/>
            </svg>
        </div>
        <p class="pf-v5-c-alert__title">${escHtml(message)}</p>
    </div>`;
}

// ── Application Controller ─────────────────────────────────────────────

const App = {
    refreshTimer: null,
    currentPage: null,

    init() {
        // Bind login form
        $('#login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            App.tryLogin();
        });
        $('#logout-btn').addEventListener('click', () => App.logout());
        $('#nav-toggle').addEventListener('click', () => {
            const sidebar = $('#page-sidebar');
            sidebar.classList.toggle('pf-m-collapsed');
        });

        // Check if already authenticated
        if (API.token) {
            App.showDashboard();
        } else {
            App.showLogin();
        }

        // Hash-based routing
        window.addEventListener('hashchange', () => App.route());
    },

    showLogin() {
        $('#login-overlay').style.display = 'flex';
        $('#app-shell').style.display = 'none';
        $('#token-input').value = '';
        $('#login-error').style.display = 'none';
        $('#token-input').focus();
    },

    async tryLogin() {
        const token = $('#token-input').value.trim();
        if (!token) return;

        const btn = $('#login-btn');
        btn.disabled = true;
        btn.textContent = 'Connecting...';

        try {
            // Temporarily set token for the health check
            API.token = token;
            await API.get('/admin/health');
            App.showDashboard();
        } catch (err) {
            API.token = null;
            $('#login-error').style.display = 'flex';
            $('#login-error-msg').textContent = err.message === 'Session expired'
                ? 'Invalid token — authentication failed'
                : `Connection failed: ${err.message}`;
        } finally {
            btn.disabled = false;
            btn.textContent = 'Connect';
        }
    },

    showDashboard() {
        $('#login-overlay').style.display = 'none';
        $('#app-shell').style.display = 'block';
        App.route();
    },

    logout() {
        App.stopAutoRefresh();
        API.token = null;
        App.showLogin();
    },

    route() {
        const hash = (location.hash || '#health').replace('#', '');
        const page = hash || 'health';

        // Update nav highlight
        $$('#nav-list .pf-v5-c-nav__link').forEach(link => {
            link.classList.toggle('pf-m-current', link.dataset.page === page);
        });

        // Close any open panels
        App.closeCaDetail();

        // Stop previous auto-refresh
        App.stopAutoRefresh();

        App.currentPage = page;

        switch (page) {
            case 'health': Pages.health(); break;
            case 'cas':    Pages.cas();    break;
            case 'otp':    Pages.otp();    break;
            case 'certs':  Pages.certs();  break;
            case 'est':    Pages.est();    break;
            default:       Pages.health(); break;
        }
    },

    startAutoRefresh(fn, ms) {
        App.stopAutoRefresh();
        App.refreshTimer = setInterval(fn, ms);
    },

    stopAutoRefresh() {
        if (App.refreshTimer) {
            clearInterval(App.refreshTimer);
            App.refreshTimer = null;
        }
    },

    setContent(html) {
        $('#main-content').innerHTML = html;
    },

    setVersion(ver) {
        $('#version-label').textContent = `v${ver}`;
    },

    // ── OTP Modal ──────────────────────────────────────────────────
    showOtpModal(token, entityId, expiresAt) {
        $('#otp-token-display').value = token;
        $('#otp-modal-entity').textContent = `Entity: ${entityId}`;
        $('#otp-modal-expires').textContent = `Expires: ${fmtTime(expiresAt)}`;
        $('#otp-modal').style.display = 'flex';
    },

    closeOtpModal() {
        $('#otp-modal').style.display = 'none';
    },

    async copyOtpToken() {
        const token = $('#otp-token-display').value;
        try {
            await navigator.clipboard.writeText(token);
            const btn = $('#otp-copy-btn');
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
        } catch {
            // Fallback: select the text
            $('#otp-token-display').select();
        }
    },

    // ── CA Detail Panel ────────────────────────────────────────────
    async showCaDetail(caId) {
        const panel = $('#ca-detail-panel');
        const body = $('#ca-detail-body');
        panel.style.display = 'block';
        body.innerHTML = spinnerHtml('md');

        try {
            const ca = await API.get(`/admin/cas/${encodeURIComponent(caId)}`);
            $('#ca-detail-title').textContent = `CA: ${ca.id}`;
            body.innerHTML = `<dl class="kipuka-dl-grid">
                <dt>ID</dt><dd class="kipuka-mono">${escHtml(ca.id)}</dd>
                <dt>Subject CN</dt><dd>${escHtml(ca.subject_cn || '—')}</dd>
                <dt>Default</dt><dd>${ca.is_default ? 'Yes' : 'No'}</dd>
                <dt>Key Type</dt><dd class="kipuka-mono">${escHtml(ca.key_type)}</dd>
                <dt>Algorithm</dt><dd class="kipuka-mono">${escHtml(ca.hash_algorithm)}</dd>
                <dt>Validity</dt><dd>${ca.validity_days} days</dd>
                <dt>Health</dt><dd>${labelHtml(ca.health, statusColor(ca.health))}</dd>
                <dt>HSM Backed</dt><dd>${ca.hsm_backed ? 'Yes' : 'No'}</dd>
                <dt>CA/B Forum</dt><dd>${ca.cab_forum_compliant ? 'Compliant' : 'Non-compliant'}</dd>
                <dt>CRL URL</dt><dd>${ca.crl_url ? `<a href="${escHtml(ca.crl_url)}" target="_blank" class="kipuka-mono">${escHtml(ca.crl_url)}</a>` : '—'}</dd>
                <dt>OCSP URL</dt><dd>${ca.ocsp_url ? `<a href="${escHtml(ca.ocsp_url)}" target="_blank" class="kipuka-mono">${escHtml(ca.ocsp_url)}</a>` : '—'}</dd>
            </dl>`;
        } catch (err) {
            body.innerHTML = alertHtml(`Failed to load CA details: ${err.message}`, 'danger');
        }
    },

    closeCaDetail() {
        $('#ca-detail-panel').style.display = 'none';
    },
};

// ── Pages ──────────────────────────────────────────────────────────────

const Pages = {

    // ── Health Page ────────────────────────────────────────────────
    async health() {
        App.setContent(spinnerHtml('lg'));

        const render = async () => {
            try {
                const data = await API.get('/admin/health');
                App.setVersion(data.version);

                const statusClass = `status-${data.status}`;
                const dbStatus = data.database?.status || 'unknown';
                const dbLatency = data.database?.latency_ms != null ? `${data.database.latency_ms}ms` : '—';
                const hsmStatus = data.hsm ? data.hsm.status : 'Not configured';
                const hsmDetail = data.hsm?.detail || '';

                App.setContent(`
                    <div class="kipuka-page-header">
                        <h1 class="pf-v5-c-title pf-m-2xl">System Health</h1>
                        <span class="pf-v5-u-color-200 pf-v5-u-font-size-sm">Auto-refreshes every 10s</span>
                    </div>
                    <div class="kipuka-health-grid">

                        <div class="pf-v5-c-card kipuka-health-card">
                            <div class="pf-v5-c-card__header">
                                <div class="pf-v5-c-card__header-main">
                                    <span class="kipuka-card-label">Overall Status</span>
                                </div>
                            </div>
                            <div class="pf-v5-c-card__body">
                                <span class="kipuka-card-metric ${statusClass}">${escHtml(data.status.toUpperCase())}</span>
                            </div>
                        </div>

                        <div class="pf-v5-c-card kipuka-health-card">
                            <div class="pf-v5-c-card__header">
                                <div class="pf-v5-c-card__header-main">
                                    <span class="kipuka-card-label">Database</span>
                                </div>
                            </div>
                            <div class="pf-v5-c-card__body">
                                <span class="kipuka-card-metric status-${dbStatus}">${escHtml(dbStatus.toUpperCase())}</span>
                                <span class="pf-v5-u-color-200">Latency: ${escHtml(dbLatency)}</span>
                            </div>
                        </div>

                        <div class="pf-v5-c-card kipuka-health-card">
                            <div class="pf-v5-c-card__header">
                                <div class="pf-v5-c-card__header-main">
                                    <span class="kipuka-card-label">HSM</span>
                                </div>
                            </div>
                            <div class="pf-v5-c-card__body">
                                <span class="kipuka-card-metric ${data.hsm ? 'status-' + data.hsm.status : ''}">${escHtml(hsmStatus.toUpperCase())}</span>
                                ${hsmDetail ? `<span class="pf-v5-u-color-200">${escHtml(hsmDetail)}</span>` : ''}
                            </div>
                        </div>

                        <div class="pf-v5-c-card kipuka-health-card">
                            <div class="pf-v5-c-card__header">
                                <div class="pf-v5-c-card__header-main">
                                    <span class="kipuka-card-label">Certificate Authorities</span>
                                </div>
                            </div>
                            <div class="pf-v5-c-card__body">
                                <span class="kipuka-card-metric ${data.healthy_ca_count === data.ca_count ? 'status-healthy' : 'status-degraded'}">${data.healthy_ca_count} / ${data.ca_count}</span>
                                <span class="pf-v5-u-color-200">Healthy / Total</span>
                            </div>
                        </div>

                        <div class="pf-v5-c-card kipuka-health-card">
                            <div class="pf-v5-c-card__header">
                                <div class="pf-v5-c-card__header-main">
                                    <span class="kipuka-card-label">Uptime</span>
                                </div>
                            </div>
                            <div class="pf-v5-c-card__body">
                                <span class="kipuka-card-metric">${escHtml(fmtUptime(data.uptime_secs))}</span>
                            </div>
                        </div>

                        <div class="pf-v5-c-card kipuka-health-card">
                            <div class="pf-v5-c-card__header">
                                <div class="pf-v5-c-card__header-main">
                                    <span class="kipuka-card-label">Version</span>
                                </div>
                            </div>
                            <div class="pf-v5-c-card__body">
                                <span class="kipuka-card-metric kipuka-mono">${escHtml(data.version)}</span>
                            </div>
                        </div>

                    </div>
                `);
            } catch (err) {
                if (App.currentPage === 'health') {
                    App.setContent(alertHtml(`Failed to fetch health data: ${err.message}`, 'danger'));
                }
            }
        };

        await render();
        App.startAutoRefresh(render, 10000);
    },

    // ── Certificate Authorities Page ───────────────────────────────
    async cas() {
        App.setContent(spinnerHtml('lg'));

        try {
            const cas = await API.get('/admin/cas');

            if (!cas || cas.length === 0) {
                App.setContent(`
                    <div class="kipuka-page-header">
                        <h1 class="pf-v5-c-title pf-m-2xl">Certificate Authorities</h1>
                    </div>
                    <div class="pf-v5-c-empty-state kipuka-empty-state">
                        <div class="pf-v5-c-empty-state__content">
                            <h2 class="pf-v5-c-title pf-m-lg">No CAs Configured</h2>
                            <div class="pf-v5-c-empty-state__body">
                                Configure certificate authorities in <code>kipuka.toml</code> to get started.
                            </div>
                        </div>
                    </div>
                `);
                return;
            }

            const rows = cas.map(ca => `
                <tr class="kipuka-clickable" onclick="App.showCaDetail('${escHtml(ca.id)}')">
                    <td class="kipuka-mono">${escHtml(ca.id)}</td>
                    <td>${ca.is_default ? labelHtml('Default', 'blue') : '—'}</td>
                    <td class="kipuka-mono">${escHtml(ca.key_type)}</td>
                    <td class="kipuka-mono">${escHtml(ca.hash_algorithm)}</td>
                    <td>${ca.validity_days}</td>
                    <td>${labelHtml(ca.health, statusColor(ca.health))}</td>
                    <td>${ca.hsm_backed ? 'Yes' : 'No'}</td>
                </tr>
            `).join('');

            App.setContent(`
                <div class="kipuka-page-header">
                    <h1 class="pf-v5-c-title pf-m-2xl">Certificate Authorities</h1>
                </div>
                <div class="kipuka-table-wrapper">
                    <table class="pf-v5-c-table pf-m-grid-md" role="grid">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Default</th>
                                <th>Key Type</th>
                                <th>Algorithm</th>
                                <th>Validity (days)</th>
                                <th>Health</th>
                                <th>HSM</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows}
                        </tbody>
                    </table>
                </div>
                <p class="pf-v5-u-color-200 pf-v5-u-font-size-sm pf-v5-u-mt-md">Click a row to view CA details.</p>
            `);
        } catch (err) {
            App.setContent(alertHtml(`Failed to load CAs: ${err.message}`, 'danger'));
        }
    },

    // ── OTP Management Page ────────────────────────────────────────
    async otp() {
        App.setContent(`
            <div class="kipuka-page-header">
                <h1 class="pf-v5-c-title pf-m-2xl">OTP Management</h1>
            </div>

            <div class="pf-v5-c-card kipuka-otp-form-card">
                <div class="pf-v5-c-card__header">
                    <div class="pf-v5-c-card__header-main">
                        <span class="pf-v5-c-title pf-m-lg">Generate OTP</span>
                    </div>
                </div>
                <div class="pf-v5-c-card__body">
                    <div id="otp-form-alert"></div>
                    <form id="otp-generate-form" onsubmit="return false;">
                        <div class="kipuka-otp-form-row">
                            <div class="pf-v5-c-form__group">
                                <label class="pf-v5-c-form__label" for="otp-entity-id">
                                    <span class="pf-v5-c-form__label-text">Entity ID</span>
                                    <span class="pf-v5-c-form__label-required" aria-hidden="true">*</span>
                                </label>
                                <div class="pf-v5-c-form__group-control">
                                    <input class="pf-v5-c-form-control" type="text" id="otp-entity-id"
                                           placeholder="device-001.example.com" required>
                                </div>
                            </div>
                            <div class="pf-v5-c-form__group">
                                <label class="pf-v5-c-form__label" for="otp-ttl">
                                    <span class="pf-v5-c-form__label-text">TTL (seconds)</span>
                                </label>
                                <div class="pf-v5-c-form__group-control">
                                    <input class="pf-v5-c-form-control" type="number" id="otp-ttl"
                                           placeholder="3600" min="1">
                                </div>
                            </div>
                            <div class="pf-v5-c-form__group">
                                <label class="pf-v5-c-form__label" for="otp-max-uses">
                                    <span class="pf-v5-c-form__label-text">Max Uses</span>
                                </label>
                                <div class="pf-v5-c-form__group-control">
                                    <input class="pf-v5-c-form-control" type="number" id="otp-max-uses"
                                           placeholder="1" min="1">
                                </div>
                            </div>
                            <div class="kipuka-form-action">
                                <button class="pf-v5-c-button pf-m-primary" type="submit" id="otp-generate-btn">
                                    Generate
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <div class="pf-v5-c-card">
                <div class="pf-v5-c-card__header">
                    <div class="pf-v5-c-card__header-main">
                        <span class="pf-v5-c-title pf-m-lg">Active OTPs</span>
                    </div>
                </div>
                <div class="pf-v5-c-card__body" id="otp-table-body">
                    ${spinnerHtml('md')}
                </div>
            </div>
        `);

        // Bind form
        $('#otp-generate-form').addEventListener('submit', () => Pages.generateOtp());

        // Load OTP list
        Pages.loadOtpTable();
    },

    async generateOtp() {
        const entityId = $('#otp-entity-id').value.trim();
        if (!entityId) return;

        const ttl = $('#otp-ttl').value ? parseInt($('#otp-ttl').value, 10) : undefined;
        const maxUsage = $('#otp-max-uses').value ? parseInt($('#otp-max-uses').value, 10) : undefined;

        const btn = $('#otp-generate-btn');
        btn.disabled = true;
        btn.textContent = 'Generating...';
        $('#otp-form-alert').innerHTML = '';

        try {
            const body = { entity_id: entityId };
            if (ttl) body.ttl_seconds = ttl;
            if (maxUsage) body.max_usage = maxUsage;

            const resp = await API.post('/admin/otp/generate', body);
            App.showOtpModal(resp.token, resp.entity_id, resp.expires_at);

            // Clear form and refresh table
            $('#otp-entity-id').value = '';
            $('#otp-ttl').value = '';
            $('#otp-max-uses').value = '';
            Pages.loadOtpTable();
        } catch (err) {
            $('#otp-form-alert').innerHTML = alertHtml(`Failed to generate OTP: ${err.message}`, 'danger');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Generate';
        }
    },

    async loadOtpTable() {
        const container = $('#otp-table-body');
        if (!container) return;

        try {
            const otps = await API.get('/admin/otp');

            if (!otps || otps.length === 0) {
                container.innerHTML = `
                    <div class="pf-v5-c-empty-state pf-m-sm">
                        <div class="pf-v5-c-empty-state__content">
                            <p class="pf-v5-u-color-200">No active OTPs. Generate one above.</p>
                        </div>
                    </div>
                `;
                return;
            }

            const rows = otps.map(otp => `
                <tr>
                    <td class="kipuka-mono">${escHtml(otp.id)}</td>
                    <td>${escHtml(otp.entity_id)}</td>
                    <td>${fmtTime(otp.expires_at)}</td>
                    <td>${otp.max_usage}</td>
                    <td>${otp.usage_count}</td>
                    <td>${fmtTime(otp.created_at)}</td>
                    <td>
                        <button class="pf-v5-c-button pf-m-danger pf-m-small"
                                onclick="Pages.revokeOtp('${escHtml(otp.id)}')"
                                title="Revoke this OTP">
                            Revoke
                        </button>
                    </td>
                </tr>
            `).join('');

            container.innerHTML = `
                <table class="pf-v5-c-table pf-m-compact pf-m-grid-md" role="grid">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Entity ID</th>
                            <th>Expires At</th>
                            <th>Max Uses</th>
                            <th>Used</th>
                            <th>Created</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                    </tbody>
                </table>
            `;
        } catch (err) {
            container.innerHTML = alertHtml(`Failed to load OTPs: ${err.message}`, 'danger');
        }
    },

    async revokeOtp(id) {
        if (!confirm(`Revoke OTP ${id}? This cannot be undone.`)) return;

        try {
            await API.del(`/admin/otp/${encodeURIComponent(id)}`);
            Pages.loadOtpTable();
        } catch (err) {
            alert(`Failed to revoke OTP: ${err.message}`);
        }
    },

    // ── Certificates Page ──────────────────────────────────────────
    async certs() {
        App.setContent(spinnerHtml('lg'));

        try {
            const certs = await API.get('/admin/certs');

            if (!certs || certs.length === 0) {
                App.setContent(`
                    <div class="kipuka-page-header">
                        <h1 class="pf-v5-c-title pf-m-2xl">Certificates</h1>
                    </div>
                    <div class="pf-v5-c-empty-state kipuka-empty-state">
                        <div class="pf-v5-c-empty-state__content">
                            <svg class="pf-v5-svg pf-v5-u-mb-md" viewBox="0 0 512 512" width="48" height="48" fill="currentColor" style="color: #6a6e73;">
                                <path d="M256 0c4.6 0 9.2 1 13.4 2.9L457.7 82.8c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-226.5 354.3c-5.2 2.1-11 2.1-16.1 0C68.8 420.7 28 239.2 27.5 140c-.1-26.2 16.3-47.9 38.3-57.2L254.6 2.9C258.8 1 263.4 0 268 0h-12zM128 256a128 128 0 1 0 256 0 128 128 0 1 0 -256 0zm96 0c0-17.7 14.3-32 32-32s32 14.3 32 32-14.3 32-32 32-32-14.3-32-32z"/>
                            </svg>
                            <h2 class="pf-v5-c-title pf-m-lg">No Certificates Issued</h2>
                            <div class="pf-v5-c-empty-state__body">
                                Use the EST endpoint to enroll devices and issue certificates.
                            </div>
                        </div>
                    </div>
                `);
                return;
            }

            const rows = certs.map(cert => {
                const color = statusColor(cert.status);
                return `
                    <tr>
                        <td class="kipuka-mono">${escHtml(cert.serial)}</td>
                        <td>${escHtml(cert.subject)}</td>
                        <td class="kipuka-mono">${escHtml(cert.ca_id)}</td>
                        <td>${fmtTime(cert.issued_at)}</td>
                        <td>${fmtTime(cert.expires_at)}</td>
                        <td>${labelHtml(cert.status, color)}</td>
                    </tr>
                `;
            }).join('');

            App.setContent(`
                <div class="kipuka-page-header">
                    <h1 class="pf-v5-c-title pf-m-2xl">Certificates</h1>
                </div>
                <div class="kipuka-table-wrapper">
                    <table class="pf-v5-c-table pf-m-grid-md" role="grid">
                        <thead>
                            <tr>
                                <th>Serial</th>
                                <th>Subject</th>
                                <th>CA</th>
                                <th>Issued</th>
                                <th>Expires</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows}
                        </tbody>
                    </table>
                </div>
            `);
        } catch (err) {
            App.setContent(alertHtml(`Failed to load certificates: ${err.message}`, 'danger'));
        }
    },

    // ── EST Endpoints Page ─────────────────────────────────────────
    est() {
        const endpoints = [
            { path: '/.well-known/est/cacerts',        method: 'GET',  status: 'Implemented',     color: 'green',  testable: true },
            { path: '/.well-known/est/simpleenroll',   method: 'POST', status: 'Implemented',     color: 'green',  testable: false },
            { path: '/.well-known/est/simplereenroll', method: 'POST', status: 'Implemented',     color: 'green',  testable: false },
            { path: '/.well-known/est/csrattrs',       method: 'GET',  status: 'Implemented',     color: 'green',  testable: false },
            { path: '/.well-known/est/serverkeygen',   method: 'POST', status: 'Not implemented', color: 'grey',   testable: false },
            { path: '/.well-known/est/fullcmc',        method: 'POST', status: 'Not implemented', color: 'grey',   testable: false },
            { path: '/.well-known/est/cms/*',          method: 'POST', status: 'Not implemented', color: 'grey',   testable: false },
            { path: '/.well-known/est/cmp',            method: 'POST', status: 'Not implemented', color: 'grey',   testable: false },
            { path: '/.well-known/est/star',           method: 'POST', status: 'Partial',         color: 'yellow', testable: false },
        ];

        const rows = endpoints.map(ep => `
            <tr>
                <td class="kipuka-mono">${escHtml(ep.path)}</td>
                <td>${escHtml(ep.method)}</td>
                <td>${labelHtml(ep.status, ep.color)}</td>
                <td>
                    ${ep.testable ? `<button class="pf-v5-c-button pf-m-secondary pf-m-small" onclick="Pages.testCacerts()">Quick Test</button>` : ''}
                </td>
            </tr>
        `).join('');

        App.setContent(`
            <div class="kipuka-page-header">
                <h1 class="pf-v5-c-title pf-m-2xl">EST Endpoints</h1>
            </div>
            <div class="pf-v5-c-card pf-v5-u-mb-lg">
                <div class="pf-v5-c-card__header">
                    <div class="pf-v5-c-card__header-main">
                        <span class="pf-v5-c-title pf-m-md">RFC 7030 Endpoint Status</span>
                    </div>
                </div>
                <div class="pf-v5-c-card__body">
                    <table class="pf-v5-c-table pf-m-compact pf-m-grid-md" role="grid">
                        <thead>
                            <tr>
                                <th>Endpoint</th>
                                <th>Method</th>
                                <th>Status</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows}
                        </tbody>
                    </table>
                </div>
            </div>
            <div id="est-test-result"></div>
        `);
    },

    async testCacerts() {
        const resultDiv = $('#est-test-result');
        resultDiv.innerHTML = spinnerHtml('md');

        try {
            const resp = await fetch('/.well-known/est/cacerts', {
                headers: { 'Accept': 'application/pkcs7-mime' },
            });

            if (resp.ok) {
                const contentType = resp.headers.get('content-type') || '';
                const size = resp.headers.get('content-length') || 'unknown';
                resultDiv.innerHTML = `
                    <div class="pf-v5-c-alert pf-m-success pf-m-inline">
                        <div class="pf-v5-c-alert__icon">
                            <svg class="pf-v5-svg" viewBox="0 0 512 512" width="16" height="16">
                                <path d="M256 0C114.6 0 0 114.6 0 256s114.6 256 256 256 256-114.6 256-256S397.4 0 256 0zm113.1 169.1l-128 160c-5.5 6.8-13.6 10.9-22.3 10.9-8.7.1-16.9-3.9-22.4-10.7l-64-80c-10.5-13.1-8.4-32.3 4.8-42.8s32.3-8.4 42.8 4.8L219 264l105.2-131.5c10.3-12.9 29.4-15.1 42.3-4.8s15.1 29.4 4.6 42.4v-1z" fill="currentColor"/>
                            </svg>
                        </div>
                        <p class="pf-v5-c-alert__title">/cacerts responded successfully</p>
                        <div class="pf-v5-c-alert__description">
                            <p>Content-Type: <code>${escHtml(contentType)}</code></p>
                            <p>Content-Length: <code>${escHtml(size)} bytes</code></p>
                            <p>Status: <code>${resp.status} ${resp.statusText}</code></p>
                        </div>
                    </div>
                `;
            } else {
                resultDiv.innerHTML = alertHtml(
                    `/cacerts returned ${resp.status} ${resp.statusText}`,
                    'danger'
                );
            }
        } catch (err) {
            resultDiv.innerHTML = alertHtml(
                `Failed to reach /cacerts: ${err.message}`,
                'danger'
            );
        }
    },
};

// ── Expose globally for onclick handlers ───────────────────────────────

window.App = App;
window.Pages = Pages;

// ── Bootstrap ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => App.init());
