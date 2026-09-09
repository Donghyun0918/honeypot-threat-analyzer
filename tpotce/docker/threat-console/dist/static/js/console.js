// Threat Console — Korean UI logic
const API = (path) => `/threat-console${path}`;

// ── Tab switching ─────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
        const target = btn.dataset.tab;
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${target}`).classList.add('active');

        // Lazy-load each tab on first activation
        if (!btn.dataset.loaded) {
            btn.dataset.loaded = '1';
            if (target === 'ml')      loadMLTab();
            if (target === 'llm')     loadLLMTab();
            if (target === 'reports') loadReportsTab();
            if (target === 'train')   loadTrainTab();
        }
    });
});

// ── Chart factory ─────────────────────────────────────────────────────────
const ACCENT = '#e20074';
const CHART_DEFAULTS = {
    plugins: { legend: { labels: { color: '#e8e8e8' } } },
    scales: {
        x: { ticks: { color: '#888' }, grid: { color: '#222' } },
        y: { ticks: { color: '#888' }, grid: { color: '#222' } }
    },
    maintainAspectRatio: false,
    responsive: true,
};
const charts = {};

function makeBar(canvasId, labels, data, label = '건수', color = ACCENT) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    if (charts[canvasId]) charts[canvasId].destroy();
    charts[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: { labels, datasets: [{ label, data, backgroundColor: color }] },
        options: { ...CHART_DEFAULTS }
    });
}

function makeLine(canvasId, labels, data, label = '건수') {
    const ctx = document.getElementById(canvasId).getContext('2d');
    if (charts[canvasId]) charts[canvasId].destroy();
    charts[canvasId] = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label, data,
                borderColor: ACCENT,
                backgroundColor: 'rgba(226,0,116,0.15)',
                tension: 0.3, fill: true,
            }]
        },
        options: { ...CHART_DEFAULTS }
    });
}

function makeDoughnut(canvasId, labels, data, palette) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    if (charts[canvasId]) charts[canvasId].destroy();
    charts[canvasId] = new Chart(ctx, {
        type: 'doughnut',
        data: { labels, datasets: [{ data, backgroundColor: palette }] },
        options: {
            plugins: { legend: { position: 'right', labels: { color: '#e8e8e8' } } },
            maintainAspectRatio: false, responsive: true,
        }
    });
}

// ── Overview ──────────────────────────────────────────────────────────────
async function loadOverview() {
    try {
        const r = await fetch(API('/api/overview')).then(r => r.json());
        document.getElementById('stat-events').textContent  = (r.total_events  || 0).toLocaleString();
        document.getElementById('stat-attacks').textContent = (r.total_attacks || 0).toLocaleString();
        document.getElementById('stat-high').textContent    = (r.high_risk     || 0).toLocaleString();
        document.getElementById('stat-llm').textContent     = (r.llm_analyzed  || 0).toLocaleString();
    } catch (e) { console.error('overview failed', e); }

    try {
        const ml = await fetch(API('/api/ml-stats?since=now-24h')).then(r => r.json());
        const tlLabels = ml.by_hour.map(b => b.ts.slice(11, 16));
        const tlData   = ml.by_hour.map(b => b.count);
        makeLine('chart-timeline', tlLabels, tlData, '시간당 분류 이벤트');

        const sdLabels = ml.score_dist.map(b => `${b.score}-${b.score+10}`);
        const sdData   = ml.score_dist.map(b => b.count);
        makeBar('chart-score', sdLabels, sdData, 'MITRE 점수');
    } catch (e) { console.error('overview charts failed', e); }
}

// ── ML tab ────────────────────────────────────────────────────────────────
async function loadMLTab() {
    // ML CSV/JSON download links (7d window)
    const mlCsv  = document.getElementById('ml-export-csv');
    const mlJson = document.getElementById('ml-export-json');
    if (mlCsv)  mlCsv.href  = API('/api/export/ml?since=now-7d&format=csv');
    if (mlJson) mlJson.href = API('/api/export/ml?since=now-7d&format=json');

    try {
        const ml = await fetch(API('/api/ml-stats?since=now-7d')).then(r => r.json());
        const palette = ['#e20074', '#ff8c00', '#ffd23f', '#4ec9b0', '#888'];
        makeDoughnut('chart-labels',
            ml.labels.map(b => b.key),
            ml.labels.map(b => b.count),
            palette);
        makeBar('chart-honeypots',
            ml.honeypots.map(b => b.key),
            ml.honeypots.map(b => b.count),
            '공격 수');
        renderModelPills(ml.model_used || []);
    } catch (e) { console.error('ML tab failed', e); }
}

function renderModelPills(buckets) {
    const total = buckets.reduce((s, b) => s + b.count, 0);
    const el = document.getElementById('model-pills');
    if (!el) return;
    if (!total) {
        el.innerHTML = '<span class="muted">데이터 없음</span>';
        return;
    }
    const labels = { ml: 'ML 모델', rule: '규칙 폴백' };
    el.innerHTML = buckets.map(b => {
        const pct = (b.count / total * 100).toFixed(1);
        const cls = b.key === 'ml' ? 'ml' : 'rule';
        return `<span class="pill ${cls}">
            ${labels[b.key] || b.key}
            <span class="pct">${pct}%</span>
            <span class="n">(${b.count.toLocaleString()})</span>
        </span>`;
    }).join('');
}

// ── LLM tab ───────────────────────────────────────────────────────────────
const SEV_PALETTE = { CRITICAL: '#ff3b3b', HIGH: '#ff8c00', MEDIUM: '#ffd23f', LOW: '#4ec9b0' };

async function loadLLMTab() {
    const since = document.getElementById('llm-since').value;
    const sev   = document.getElementById('sev-filter').value;

    // Update export links every time
    const csv  = document.getElementById('llm-export-csv');
    const json = document.getElementById('llm-export-json');
    if (csv)  csv.href  = API(`/api/export/llm?since=${since}&format=csv`);
    if (json) json.href = API(`/api/export/llm?since=${since}&format=json`);

    try {
        const stats = await fetch(API(`/api/llm-stats?since=${since}`)).then(r => r.json());
        makeDoughnut('chart-severity',
            stats.severity.map(b => b.key),
            stats.severity.map(b => b.count),
            stats.severity.map(b => SEV_PALETTE[b.key] || '#888'));
        makeBar('chart-risk',
            stats.risk_dist.map(b => `${b.score}–${b.score+1}`),
            stats.risk_dist.map(b => b.count),
            '건수');
    } catch (e) { console.error('LLM stats failed', e); }

    try {
        const url = `/api/llm-recent?since=${since}&size=50` + (sev ? `&severity=${sev}` : '');
        const res = await fetch(API(url)).then(r => r.json());
        renderLLMRows(res.items);
    } catch (e) { console.error('LLM list failed', e); }
}

function renderLLMRows(items) {
    const tbody = document.getElementById('llm-rows');
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#666;padding:40px;">데이터 없음 — LLM 분석기가 아직 실행되지 않았거나, 해당 기간에 고위험 이벤트가 없습니다.</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(it => {
        const ts = (it['@timestamp'] || '').replace('T', ' ').slice(0, 19);
        const sev = (it.severity || 'MEDIUM').toUpperCase();
        return `<tr>
            <td>${ts}</td>
            <td><span class="sev-badge sev-${sev}">${sev}</span></td>
            <td>${(it.risk_score ?? 0).toFixed(1)}</td>
            <td><code>${escapeHtml(it.src_ip || '')}</code></td>
            <td>${escapeHtml(it.honeypot || '')}</td>
            <td class="summary-cell">${escapeHtml(it.summary_ko || '')}</td>
        </tr>`;
    }).join('');
}

document.getElementById('llm-refresh')?.addEventListener('click', loadLLMTab);
document.getElementById('sev-filter')?.addEventListener('change', loadLLMTab);
document.getElementById('llm-since')?.addEventListener('change', loadLLMTab);

// ── Reports tab ───────────────────────────────────────────────────────────
async function loadReportsTab() {
    try {
        const res = await fetch(API('/api/reports')).then(r => r.json());
        renderReportList(res.items || []);
    } catch (e) { console.error('reports failed', e); }
}

function renderReportList(items) {
    const ul = document.getElementById('report-list');
    if (!items.length) {
        ul.innerHTML = '<li style="color:#666;justify-content:center;">생성된 리포트가 없습니다.</li>';
        return;
    }
    ul.innerHTML = items.map(it => {
        const ts = it.created_at.slice(0, 19).replace('T', ' ');
        const kb = (it.size_bytes / 1024).toFixed(1);
        return `<li>
            <span><a href="${API('/api/report/' + it.id)}">threat-report-${it.id}.pdf</a></span>
            <span class="meta">${ts} · ${kb} KB</span>
        </li>`;
    }).join('');
}

document.getElementById('report-generate')?.addEventListener('click', async () => {
    const btn = document.getElementById('report-generate');
    const status = document.getElementById('report-status');
    const since = document.getElementById('report-since').value;

    btn.disabled = true;
    status.textContent = '생성 중…';
    status.className = 'status';

    try {
        const r = await fetch(API('/api/report'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ since }),
        }).then(r => r.json());

        if (r.error) throw new Error(r.error);
        status.textContent = `생성 완료 (${(r.size_bytes/1024).toFixed(1)} KB)`;
        status.className = 'status ok';
        loadReportsTab();
    } catch (e) {
        status.textContent = `오류: ${e.message}`;
        status.className = 'status err';
    } finally {
        btn.disabled = false;
    }
});

// ── Training tab ──────────────────────────────────────────────────────────
async function loadTrainTab() {
    await refreshActiveModel();
    await refreshJobs();

    // Build dataset (ES auto)
    document.getElementById('ds-build')?.addEventListener('click', async () => {
        const since    = document.getElementById('ds-since').value;
        const max      = parseInt(document.getElementById('ds-max').value, 10);
        const balanceN = parseInt(document.getElementById('ds-balance-n').value || '0', 10);
        const normalN  = parseInt(document.getElementById('ds-normal-n').value || '0', 10);
        const status = document.getElementById('ds-status');
        status.textContent = '데이터셋 생성 요청 중…';
        status.className = 'job-status running';
        try {
            const r = await fetch(API('/api/train/dataset'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ since, max, balance_n: balanceN, normal_n: normalN }),
            }).then(r => r.json());
            if (r.error) throw new Error(r.error);
            status.textContent = `작업 ${r.job_id} 큐 등록됨`;
            pollJob(r.job_id, status, () => refreshJobs());
        } catch (e) {
            status.textContent = `오류: ${e.message}`;
            status.className = 'job-status failed';
        }
    });

    // BYOM — Upload a pre-trained model directly into ml-classifier's active dir
    document.getElementById('byom-submit')?.addEventListener('click', async () => {
        const model = document.getElementById('byom-model').files[0];
        const enc   = document.getElementById('byom-encoders').files[0];
        const status = document.getElementById('byom-status');
        if (!model) {
            status.textContent = 'multi_model.pkl 파일을 선택해 주세요';
            status.className = 'job-status failed';
            return;
        }
        const fd = new FormData();
        fd.append('model', model);
        if (enc) fd.append('encoders', enc);
        status.textContent = '업로드 + 검증 중…';
        status.className = 'job-status running';
        try {
            const r = await fetch(API('/api/model/upload'), { method: 'POST', body: fd }).then(r => r.json());
            if (r.error) throw new Error(r.error);
            status.textContent = `활성화 완료 (${r.model_class}): ${r.copied.join(', ')}`;
            status.className = 'job-status success';
            await refreshActiveModel();
        } catch (e) {
            status.textContent = `오류: ${e.message}`;
            status.className = 'job-status failed';
        }
    });

    // Upload CSV
    document.getElementById('up-submit')?.addEventListener('click', async () => {
        const train = document.getElementById('up-train').files[0];
        const test  = document.getElementById('up-test').files[0];
        const enc   = document.getElementById('up-enc').files[0];
        const status = document.getElementById('up-status');
        if (!train) { status.textContent = 'train.csv 파일을 선택해 주세요'; status.className = 'job-status failed'; return; }
        const fd = new FormData();
        fd.append('train', train);
        if (test) fd.append('test', test);
        if (enc)  fd.append('encoders', enc);
        status.textContent = '업로드 중…';
        status.className = 'job-status running';
        try {
            const r = await fetch(API('/api/train/upload'), { method: 'POST', body: fd }).then(r => r.json());
            if (r.error) throw new Error(r.error);
            status.textContent = `업로드 완료 (작업 ${r.job_id})`;
            status.className = 'job-status success';
            await refreshJobs();
        } catch (e) {
            status.textContent = `오류: ${e.message}`;
            status.className = 'job-status failed';
        }
    });

    // Train start
    document.getElementById('train-start')?.addEventListener('click', async () => {
        const src = document.getElementById('train-source').value;
        const status = document.getElementById('train-status');
        const logEl  = document.getElementById('train-log');
        if (!src) { status.textContent = '먼저 데이터셋을 선택하세요'; status.className = 'job-status failed'; return; }
        status.textContent = '학습 요청 (LightGBM)…';
        status.className = 'job-status running';
        logEl.textContent = '';
        const useSmote = document.getElementById('train-smote')?.checked ?? false;
        const noCv    = document.getElementById('train-no-cv')?.checked ?? false;
        try {
            const r = await fetch(API('/api/train/start'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source_job_id: src, smote: useSmote, no_cv: noCv }),
            }).then(r => r.json());
            if (r.error) throw new Error(r.error);
            status.textContent = `학습 작업 ${r.job_id} 시작`;
            pollJob(r.job_id, status, async () => {
                const j = await fetch(API('/api/train/job/' + r.job_id)).then(r => r.json());
                if (j.metrics?.multi) {
                    const m = j.metrics;
                    let cvNote = '';
                    if (m.cv) {
                        cvNote = ` | CV(5-fold) acc=${m.cv.cv_acc_mean}±${m.cv.cv_acc_std} F1=${m.cv.cv_f1_mean}±${m.cv.cv_f1_std}`;
                    }
                    status.innerHTML = `학습 완료 (LightGBM) — ` +
                        `정확도=<b>${m.multi.accuracy}</b>, macro-F1=<b>${m.multi.macro_f1}</b> · ` +
                        `train=${m.n_train.toLocaleString()} test=${m.n_test.toLocaleString()}` +
                        `<br><small style="color:#aaa">${cvNote}</small>`;
                }
                await refreshJobs();
            }, logEl);
        } catch (e) {
            status.textContent = `오류: ${e.message}`;
            status.className = 'job-status failed';
        }
    });

    // Activate
    document.getElementById('activate-start')?.addEventListener('click', async () => {
        const src = document.getElementById('activate-source').value;
        const status = document.getElementById('activate-status');
        if (!src) { status.textContent = '활성화할 학습 작업을 선택하세요'; status.className = 'job-status failed'; return; }
        status.textContent = '활성화 중…';
        status.className = 'job-status running';
        try {
            const r = await fetch(API('/api/train/activate'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ train_job_id: src }),
            }).then(r => r.json());
            if (r.error) throw new Error(r.error);
            status.innerHTML = `활성화 완료 (${r.copied.join(', ')}) — ml-classifier가 다음 폴링 사이클에 자동 reload됨`;
            status.className = 'job-status success';
            await refreshActiveModel();
        } catch (e) {
            status.textContent = `오류: ${e.message}`;
            status.className = 'job-status failed';
        }
    });

    document.getElementById('train-refresh')?.addEventListener('click', refreshJobs);
}

async function refreshActiveModel() {
    try {
        const r = await fetch(API('/api/train/active-model')).then(r => r.json());
        const el = document.getElementById('active-model-info');
        if (!r.files || !r.files.length) {
            el.innerHTML = `<span class="muted">활성 모델이 없습니다 — ml-classifier가 규칙 기반 폴백을 사용합니다.</span>`;
            return;
        }
        el.innerHTML = `<code>${r.dir}</code><br>` + r.files.map(f =>
            `<code>${f.name}</code> · ${(f.size_bytes/1024).toFixed(1)} KB · 업데이트 ${f.mtime.slice(0,19).replace('T',' ')}`
        ).join('<br>');
    } catch (e) { console.error('active model failed', e); }
}

async function refreshJobs() {
    try {
        const r = await fetch(API('/api/train/jobs')).then(r => r.json());
        const items = r.items || [];

        // Populate dataset selector (jobs that produced a dataset)
        const dsSel = document.getElementById('train-source');
        const datasets = items.filter(j =>
            (j.kind === 'dataset' || j.kind === 'upload') && j.status === 'success' && j.dataset_csv);
        dsSel.innerHTML = datasets.length
            ? datasets.map(j => `<option value="${j.id}">${j.id} · ${j.kind} · ${j.dataset_csv.split('/').pop()}</option>`).join('')
            : '<option value="">(생성된 데이터셋 없음)</option>';

        // Populate activation selector (successful train jobs)
        const aSel = document.getElementById('activate-source');
        const trains = items.filter(j => j.kind === 'train' && j.status === 'success' && j.model_dir);
        aSel.innerHTML = trains.length
            ? trains.map(j => {
                const m = j.metrics?.multi;
                const summary = m ? ` · acc=${m.accuracy} F1=${m.macro_f1}` : '';
                return `<option value="${j.id}">${j.id}${summary}</option>`;
            }).join('')
            : '<option value="">(완료된 학습 작업 없음)</option>';

        // History table
        const tbody = document.getElementById('jobs-rows');
        tbody.innerHTML = items.length ? items.map(j => {
            let note = '';
            if (j.kind === 'dataset') note = `since=${j.since||''} max=${j.max||''}`;
            else if (j.kind === 'upload') note = (j.dataset_csv||'').split('/').pop();
            else if (j.kind === 'train' && j.metrics?.multi)
                note = `Multi acc=${j.metrics.multi.accuracy} F1=${j.metrics.multi.macro_f1}`;
            const statusCls = `sev-${j.status === 'success' ? 'LOW' : j.status === 'failed' ? 'CRITICAL' : 'MEDIUM'}`;
            return `<tr>
                <td><code>${j.id}</code></td>
                <td>${j.kind || '-'}</td>
                <td><span class="sev-badge ${statusCls}">${j.status || '-'}</span></td>
                <td>${(j.updated_at||'').slice(0,19).replace('T',' ')}</td>
                <td>${escapeHtml(note)}</td>
            </tr>`;
        }).join('') : '<tr><td colspan="5" style="text-align:center;color:#666;padding:20px;">작업 이력 없음</td></tr>';
    } catch (e) { console.error('jobs failed', e); }
}

function pollJob(jobId, statusEl, onDone, logEl) {
    const tick = async () => {
        try {
            const j = await fetch(API('/api/train/job/' + jobId)).then(r => r.json());
            if (j.error) throw new Error(j.error);
            statusEl.className = `job-status ${j.status}`;
            statusEl.textContent = `[${j.id}] ${j.status}` + (j.error ? ` — ${j.error}` : '');
            if (logEl && j.log) logEl.textContent = j.log.slice(-80).join('\n');
            if (j.status === 'success' || j.status === 'failed') {
                if (onDone) onDone();
                return;
            }
        } catch (e) {
            statusEl.textContent = `폴링 오류: ${e.message}`;
            statusEl.className = 'job-status failed';
            return;
        }
        setTimeout(tick, 2000);
    };
    tick();
}

// ── Utils ─────────────────────────────────────────────────────────────────
function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, m => ({
        '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[m]));
}

// Initial load
loadOverview();
