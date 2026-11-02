// Bio Laboratory: front end. All real logic lives in the C++ server (main.cpp).
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const CMD = { LOCKDOWN: 'Lockdown', LIFT_LOCKDOWN: 'Lift lockdown', REVOKE: 'Revoke access', RESTORE: 'Restore access', ALERT: 'Security alert' };

let S = null;          // latest state from /api/state
let logSort = 'time';  // current audit-log order
let logs = [];         // rows currently shown
let hlBucket = -1;     // bucket highlighted after a lookup
let busy = false;

async function api(path, body) {
  const opt = body ? { method: 'POST', body: new URLSearchParams(body) } : {};
  const res = await fetch(path, opt);
  return res.json();
}

function say(text, ok) {
  const m = $('#msg');
  m.textContent = text;
  m.className = 'msg ' + (ok ? 'ok' : 'no');
}

/* ---------- load + render ---------- */
async function load() {
  // one round trip when the log is in time order (the state already has it that way)
  const [state, sorted] = await Promise.all([api('/api/state'), logSort === 'time' ? null : api('/api/logs?sort=' + logSort)]);
  S = state;
  logs = sorted ? sorted.logs : S.logs;
  document.querySelectorAll('.pill').forEach(p => p.classList.toggle('on', p.dataset.sort === logSort));
  $('#searchOut').textContent = '';
  render();
}

function render() {
  renderHeader();
  renderFields();
  renderQueue();
  renderStack();
  renderPeople();
  renderTree();
  renderLogs(logs);
}

function renderHeader() {
  const st = $('#status');
  st.classList.toggle('lock', S.lockdown);
  $('#statusText').textContent = S.lockdown ? 'Lockdown active' : 'Lab open';
}

function setOptions(sel, html) {
  const keep = sel.value;
  sel.innerHTML = html;
  if ([...sel.options].some(o => o.value === keep)) sel.value = keep;
}

function renderFields() {
  const zones = S.zoneList.map(z => `<option value="${z.level}">${esc(z.name)} (level ${z.level})</option>`).join('');
  setOptions($('#zoneSel'), zones);
  setOptions($('#pgZone'), zones);
  $('#ridList').innerHTML = S.researchers.map(r => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join('');
  setOptions($('#pgRes'), S.researchers.map(r => `<option value="${esc(r.id)}">${esc(r.name)} (${esc(r.id)})</option>`).join(''));
}

function renderQueue() {
  const q = S.queue;
  $('#slots').innerHTML = q.slots.map((s, i) => {
    const tags = [];
    if (s.filled && i === q.front) tags.push('<span class="tag">FRONT</span>');
    if (s.filled && i === q.rear) tags.push('<span class="tag rear">REAR</span>');
    return s.filled
      ? `<div class="slot full"><span class="ix">${i}</span><b>Ticket ${s.ticket}</b><small>ID ${esc(s.id)}, ${esc(s.zone)}</small><span class="tags">${tags.join('')}</span></div>`
      : `<div class="slot"><span class="ix">${i}</span><small>free</small></div>`;
  }).join('');
  $('#qInfo').textContent = `front = ${q.front}   rear = ${q.rear}   waiting = ${q.count} of ${q.size}`;
}

function renderStack() {
  const st = S.stack;
  $('#stackBox').innerHTML = st.items.length
    ? st.items.map((c, i) => {
        const label = CMD[c.type] + (c.target ? ' ' + c.target : '');
        return `<div class="cmd ${i === st.top ? 'top' : ''}"><span>${esc(label)}</span>${i === st.top ? '<small>TOP</small>' : ''}</div>`;
      }).join('')
    : '<span class="none">No pending commands</span>';
  $('#sInfo').textContent = `top = ${st.top}   capacity = ${st.size}`;
}

function renderPeople() {
  $('#people').innerHTML = S.researchers.map(r => `
    <tr class="${r.bucket === hlBucket ? 'hl' : ''}">
      <td><b>${r.bucket}</b>${r.pos ? ` <small>(chain ${r.pos + 1})</small>` : ''}</td>
      <td>${esc(r.id)}</td><td>${esc(r.name)}</td><td>${esc(r.role)}</td>
      <td><span class="pillst ${esc(r.status)}">${esc(r.status)}</span></td>
      <td>${r.fpReal ? '<span class="pillst Authorized">Windows Hello</span>' : `<code>${esc(r.fingerprint)}</code>`}</td><td><code>${esc(r.nfc)}</code></td>
    </tr>`).join('');
}

function zoneHtml(n, side) {
  if (!n) return '';
  const chips = n.allowed.length
    ? n.allowed.map(id => {
        const r = S.researchers.find(x => x.id === id);
        return `<button class="chip" data-zone="${n.level}" data-id="${esc(id)}" title="Remove this permission">${esc(r ? r.name : id)} &times;</button>`;
      }).join('')
    : '<span class="none">nobody yet</span>';
  const kids = [['left', n.left], ['right', n.right]].filter(k => k[1]).map(k => zoneHtml(k[1], k[0])).join('');
  return `<li><div class="znode">${side ? `<span class="side">${side}</span>` : ''}<strong>${esc(n.name)}</strong><span class="lvl">level ${n.level}</span></div>
    <div class="chips">${chips}</div>${kids ? `<ul>${kids}</ul>` : ''}</li>`;
}
function renderTree() {
  $('#tree').innerHTML = '<ul class="root">' + zoneHtml(S.zones, '') + '</ul>';
}

function logRow(e, cls) {
  return `<tr class="${cls || ''}"><td><code>${esc(e.time)}</code></td>
    <td>${esc(e.id)}${e.name ? ' ' + esc(e.name) : ''}</td><td>${esc(e.zone)}</td>
    <td><span class="pillst ${esc(e.result)}">${esc(e.result)}</span></td><td>${esc(e.reason)}</td></tr>`;
}
function renderLogs(rows, marks = {}) {
  $('#logBody').innerHTML = rows.map((e, i) => logRow(e, marks[i])).join('');
}

/* ---------- door console ---------- */
const method = () => document.querySelector('input[name=method]:checked').value;

/* ---- credential method: password | nfc | fingerprint ---- */
const canWebAuthn = !!(window.PublicKeyCredential && navigator.credentials);
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

function syncMethod() {
  const m = method(), cred = $('#cred');
  cred.value = '';
  cred.type = m === 'password' ? 'password' : 'text';
  $('#credLabel').textContent = { password: 'Password', nfc: 'NFC card code', fingerprint: 'Fingerprint' }[m];
  cred.placeholder = { password: 'Enter password', nfc: 'Tap the card or type a code', fingerprint: 'Scan with the sensor' }[m];
  $('#sim').hidden = m === 'password';
  $('#sim').textContent = m === 'nfc' ? 'Tap card' : 'Scan fingerprint';
  $('#enrol').hidden = m !== 'fingerprint';
  $('#credHint').textContent = {
    password: 'Demo passwords look like name@ID, for example ananya@102.',
    nfc: 'Tap card fills in the registered card code. You can also type a wrong one to see a denial.',
    fingerprint: canWebAuthn
      ? 'Real reader: enrol once with this laptop (Windows Hello), then scan. Not enrolled? Scan falls back to a simulated code.'
      : 'This browser has no Windows Hello support, so Scan uses a simulated code.'
  }[m];
}
document.querySelectorAll('input[name=method]').forEach(r => r.onchange = syncMethod);

async function webauthnCreate(id, name) {
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: 'Bio Laboratory' },
    user: { id: new TextEncoder().encode(id), name: id, displayName: name },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
    timeout: 60000 } });
  return 'WA:' + b64u(cred.rawId);
}
async function webauthnVerify(stored) {
  await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [{ type: 'public-key', id: unb64u(stored.slice(3)) }],
    userVerification: 'required', timeout: 60000 } });
  return stored;
}

$('#sim').onclick = async () => {
  const r = S.researchers.find(x => x.id === $('#rid').value.trim());
  if (!r) { say('No registered researcher with that ID to scan', false); return; }
  if (method() === 'nfc') { $('#cred').value = r.nfc; say('Card tapped for ' + r.name, true); return; }
  if (r.fpReal) {
    try { say('Touch the fingerprint sensor...', true); $('#cred').value = await webauthnVerify(r.fingerprint); say('Fingerprint accepted for ' + r.name, true); }
    catch (e) { say('Fingerprint not accepted (' + (e.name || 'cancelled') + ')', false); }
    return;
  }
  $('#cred').value = r.fingerprint;
  say('Simulated scan for ' + r.name + ' (not enrolled with the laptop reader)', true);
};

$('#enrol').onclick = async () => {
  const r = S.researchers.find(x => x.id === $('#rid').value.trim());
  if (!r) { say('Enter a registered researcher ID first', false); return; }
  if (!canWebAuthn) { say('Use Chrome or Edge on http://localhost:8080 for Windows Hello', false); return; }
  try {
    say('Touch the fingerprint sensor to enrol ' + r.name + '...', true);
    const res = await api('/api/enroll', { id: r.id, credential: await webauthnCreate(r.id, r.name) });
    say(res.message, res.ok);
    await load();
  } catch (e) {
    say(e.name === 'SecurityError' ? 'Open this page as http://localhost:8080 (not 127.0.0.1) to use the fingerprint reader' : 'Enrolment cancelled or failed (' + (e.name || 'error') + ')', false);
  }
};

/* ---- speed setting (remembered) ---- */
const speed = () => document.querySelector('input[name=speed]:checked').value;
try { const sv = localStorage.getItem('labSpeed'); if (sv) document.querySelector(`input[name=speed][value=${sv}]`).checked = true; } catch (e) {}
document.querySelectorAll('input[name=speed]').forEach(r => r.onchange = () => { try { localStorage.setItem('labSpeed', speed()); } catch (e) {} });

/* ---- one-click entry: scan if needed, send, then decide this very ticket ---- */
$('#reqForm').onsubmit = async e => {
  e.preventDefault();
  if (busy) return;
  busy = true;
  const now = !e.submitter || e.submitter.dataset.act !== 'queue';
  try {
    const id = $('#rid').value.trim(), m = method();
    let cred = $('#cred').value.trim();
    if (!cred && m !== 'password') {                       // no code typed: scan automatically
      const r = S.researchers.find(x => x.id === id);
      if (!r) { say('No registered researcher with that ID to scan', false); return; }
      if (m === 'nfc') cred = r.nfc;
      else if (r.fpReal) {
        try { say('Touch the fingerprint sensor...', true); cred = await webauthnVerify(r.fingerprint); }
        catch (err) { say('Fingerprint not accepted (' + (err.name || 'cancelled') + ')', false); return; }
      } else cred = r.fingerprint;
    }
    const res = await api('/api/request', { id, method: m, credential: cred, zone: $('#zoneSel').value });
    say(res.message, res.ok);
    if (!res.ok) return;
    $('#cred').value = '';
    if (!now) { await load(); return; }
    let result = null;                                     // emergencies and older tickets run first, as always
    for (let i = 0; i < 30 && !result; i++) {
      const p = await api('/api/process', {});
      if (!p.ok) break;
      if (p.result.ticket === res.ticket) result = p.result;
    }
    const loaded = load();
    if (result) await showResult(result);
    await loaded;
  } finally { busy = false; }
};

const EMG_HINT = {
  LOCKDOWN: 'Use for a security threat, fire, contamination or break-in. Every entry is denied until you lift it.',
  LIFT_LOCKDOWN: 'Use when the danger is over. Normal access resumes.',
  REVOKE: 'Use for a lost card, a resigned or suspended person, or suspicious activity. Blocks that ID.',
  RESTORE: 'Use when the person is cleared or the card is found. Sets the status back to Authorized.',
  ALERT: 'Use to warn security about something suspicious. Nothing is blocked, it is only recorded.'
};
$('#emgType').onchange = () => {
  const v = $('#emgType').value, needs = ['REVOKE', 'RESTORE'].includes(v);
  $('#emgTarget').hidden = !needs;
  $('#emgTarget').required = needs;
  $('#emgHint').textContent = EMG_HINT[v];
};
$('#emgHint').textContent = EMG_HINT[$('#emgType').value];
$('#emgForm').onsubmit = async e => {
  e.preventDefault();
  const res = await api('/api/emergency', { type: $('#emgType').value, target: $('#emgTarget').value.trim() });
  say(res.message, res.ok);
  if (res.ok) await load();
};

$('#processBtn').onclick = async () => {
  if (busy) return;
  busy = true;
  $('#processBtn').disabled = true;
  const res = await api('/api/process', {});
  if (!res.ok) {
    say(res.message, false);
  } else {
    say('', true);
    load();
    await showResult(res.result);
  }
  $('#processBtn').disabled = false;
  busy = false;
};

async function showResult(r) {
  const box = $('#result');
  const icon = { granted: '&#10003;', denied: '&#10005;', emergency: '!' }[r.outcome];
  box.className = 'result ' + r.outcome;
  box.innerHTML = `<div class="res-head"><span class="res-ico">${icon}</span><div><strong>${esc(r.title)}</strong><p>${esc(r.detail)}</p></div></div><ol class="steps"></ol>`;
  box.scrollIntoView({ block: 'nearest', behavior: reduce ? 'auto' : 'smooth' });
  const ol = $('.steps', box);
  for (const s of r.steps) {
    const li = document.createElement('li');
    li.textContent = s;
    ol.appendChild(li);
    if (speed() === 'slow' && !reduce) await sleep(420);
  }
}

/* ---------- researchers ---------- */
$('#lookForm').onsubmit = async e => {
  e.preventDefault();
  const id = $('#lookId').value.trim();
  if (!id) return;
  const r = await api('/api/lookup?id=' + encodeURIComponent(id));
  hlBucket = r.bucket;
  renderPeople();
  const chain = r.chain.length ? r.chain.join(' then ') : 'empty';
  $('#lookOut').textContent = r.found
    ? `ID ${id} hashes to bucket ${r.bucket}. Chain: ${chain}. Found ${r.name} after ${r.probes} check(s).`
    : `ID ${id} hashes to bucket ${r.bucket}. Chain: ${chain}. No match after ${r.probes} check(s).`;
};

$('#regForm').onsubmit = async e => {
  e.preventDefault();
  const res = await api('/api/researcher', { id: $('#rgId').value.trim(), name: $('#rgName').value.trim(), role: $('#rgRole').value.trim(), status: $('#rgStatus').value, password: $('#rgPass').value });
  say(res.message, res.ok);
  if (res.ok) { $('#regForm').reset(); await load(); }
};

/* ---------- zones ---------- */
$('#tree').onclick = async e => {
  const b = e.target.closest('.chip');
  if (!b) return;
  const res = await api('/api/permission', { zone: b.dataset.zone, id: b.dataset.id, action: 'revoke' });
  say(res.message, res.ok);
  await load();
};
$('#permForm').onsubmit = async e => {
  e.preventDefault();
  const action = e.submitter ? e.submitter.dataset.action : 'grant';
  const res = await api('/api/permission', { zone: $('#pgZone').value, id: $('#pgRes').value, action });
  say(res.message, res.ok);
  await load();
};

/* ---------- audit log ---------- */
$('#sortPills').onclick = async e => {
  const b = e.target.closest('.pill');
  if (!b) return;
  logSort = b.dataset.sort;
  document.querySelectorAll('.pill').forEach(p => p.classList.toggle('on', p === b));
  const L = await api('/api/logs?sort=' + logSort);
  logs = L.logs;
  $('#searchOut').textContent = '';
  renderLogs(logs);
};

$('#findForm').onsubmit = async e => {
  e.preventDefault();
  const id = $('#findId').value.trim();
  if (!id || busy) return;
  busy = true;
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('on'));
  const r = await api('/api/search?id=' + encodeURIComponent(id));
  renderLogs(r.logs);
  $('#searchOut').textContent = 'Sorted by researcher ID with merge sort. Searching...';
  for (const t of r.trace) {
    const marks = {};
    for (let i = t.lo; i <= t.hi; i++) marks[i] = 'range';
    marks[t.mid] = 'mid';
    renderLogs(r.logs, marks);
    $('#searchOut').textContent = `Checking row ${t.mid}, range ${t.lo} to ${t.hi}`;
    await sleep(speed() === 'slow' && !reduce ? 800 : 150);
  }
  const marks = {};
  for (let i = 0; i < r.count; i++) marks[r.first + i] = 'match';
  renderLogs(r.logs, marks);
  $('#searchOut').textContent = r.count
    ? `Found ${r.count} record(s) for ID ${id} in ${r.steps} step(s). Reading the whole log would take up to ${r.logs.length}.`
    : `No records for ID ${id}. Binary search ruled it out in ${r.steps} step(s).`;
  busy = false;
};

$('#resetBtn').onclick = async () => {
  if (!confirm('Reset everything to the 5 sample researchers? The saved data will be replaced.')) return;
  const res = await api('/api/reset', {});
  say(res.message, res.ok);
  await load();
};

syncMethod();
load();
