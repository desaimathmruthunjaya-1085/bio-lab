// Bio Laboratory: door device. A thin screen over the C++ program (POST /api/door decides at once).
const $ = s => document.querySelector(s);
const HOLD_MS = 4000;

let S = null, person = null, zoneSel = null, busy = false, soundOn = true, resetTimer = null, audio = null;
let toAdmin = true;   // true: requests wait in the admin queue; false: the device decides at once
try { if (localStorage.getItem('doorToAdmin') === '0') toAdmin = false; } catch (e) {}

async function api(path, body) {
  const res = await fetch(path, body ? { method: 'POST', body: new URLSearchParams(body) } : {});
  return res.json();
}

/* ---------- sound (short tones, like a real reader) ---------- */
function beep(tones) {
  if (!soundOn) return;
  try {
    audio = audio || new (window.AudioContext || window.webkitAudioContext)();
    let t = audio.currentTime;
    for (const [freq, len] of tones) {
      const o = audio.createOscillator(), g = audio.createGain();
      o.frequency.value = freq; o.type = 'sine';
      g.gain.setValueAtTime(0.12, t); g.gain.exponentialRampToValueAtTime(0.001, t + len);
      o.connect(g); g.connect(audio.destination); o.start(t); o.stop(t + len);
      t += len + 0.04;
    }
  } catch (e) {}
}
$('#sound').onclick = () => {
  soundOn = !soundOn;
  $('#sound').textContent = soundOn ? 'Sound on' : 'Sound off';
  $('#sound').setAttribute('aria-pressed', String(soundOn));
};

function syncMode() {
  $('#mode').textContent = 'Send to admin: ' + (toAdmin ? 'on' : 'off');
  $('#mode').setAttribute('aria-pressed', String(toAdmin));
}
$('#mode').onclick = () => {
  toAdmin = !toAdmin; syncMode();
  try { localStorage.setItem('doorToAdmin', toAdmin ? '1' : '0'); } catch (e) {}
};
syncMode();

/* ---------- state from the C++ program ---------- */
const zoneName = () => { const z = S && S.zoneList.find(x => String(x.level) === zoneSel); return z ? z.name : ''; };
const screenState = () => $('#screen').dataset.state;

async function refresh() {
  try { S = await api('/api/state'); } catch (e) { return; }
  drawZones();
  $('#chips').innerHTML = S.researchers.slice().sort((a, b) => a.id.localeCompare(b.id)).map(r =>
    `<button type="button" class="chip" data-id="${r.id}" aria-pressed="${!!person && person.id === r.id}"><span>${r.name}</span><small>ID ${r.id}</small></button>`).join('');
  $('#banner').hidden = !S.lockdown;
  if (screenState() === 'idle') showIdle();
}
function drawZones() {
  $('#zones').innerHTML = S.zoneList.map(z =>
    `<button type="button" class="zbtn" role="radio" aria-checked="${zoneSel === String(z.level)}" data-level="${z.level}"><b>${z.name}</b><small>Level ${z.level}</small></button>`).join('');
}

/* ---------- screen states ---------- */
function setState(state, title, sub, led) {
  $('#screen').dataset.state = state;
  $('#title').textContent = title;
  $('#sub').textContent = sub || '';
  $('#led').className = 'led' + (led ? ' ' + led : '');
}
function showIdle() {
  const d = $('#detail'); if (d) d.remove();
  setState('idle', 'Where do you want to go?', zoneSel ? 'Going to ' + zoneName() + '. Now identify yourself' : 'Choose a zone, then identify yourself');
}
function setButtons(off) { for (const s of ['#tap', '#finger', '#entry .enter', '#sos']) $(s).disabled = off; }
function resetLater() {
  clearTimeout(resetTimer);
  resetTimer = setTimeout(() => {
    $('#uid').value = ''; $('#pw').value = '';
    zoneSel = null; if (S) drawZones();
    showIdle(); busy = false; setButtons(false);
    $('#uid').focus();
  }, HOLD_MS);
}
function addDetail(text) {
  const old = $('#detail'); if (old) old.remove();
  const d = document.createElement('p');
  d.className = 'detail'; d.id = 'detail'; d.textContent = text;
  $('#sub').after(d);
}

function showResult(r) {
  const granted = r.outcome === 'granted';
  setState(granted ? 'granted' : 'denied', granted ? 'ACCESS GRANTED' : 'ACCESS DENIED',
    granted ? 'Welcome, ' + r.name : r.reason, granted ? 'ok' : 'bad');
  addDetail(granted ? r.zone + ' is open' : (r.name && r.name !== 'Unknown' ? r.name + ', ' + r.zone : r.zone));
  beep(granted ? [[880, 0.12], [1175, 0.18]] : [[220, 0.2], [196, 0.3]]);
  resetLater();
}

async function attempt(id, method, credential) {
  if (busy) return;
  busy = true; setButtons(true);
  clearTimeout(resetTimer);
  const d = $('#detail'); if (d) d.remove();
  setState('busy', 'Checking...', '', '');
  if (toAdmin) {                                   // push to the admin queue and wait for security
    const q = await api('/api/request', { id, method, credential, zone: zoneSel });
    if (!q.ok) { setState('denied', 'NOT SENT', q.message, 'bad'); beep([[220, 0.25]]); resetLater(); return; }
    setState('alert', 'REQUEST SENT', 'Waiting for security approval', 'warn');
    addDetail('Ticket #' + q.ticket + ' - ' + zoneName());
    beep([[660, 0.12], [880, 0.12]]);
    resetLater();
    refresh();
    return;
  }
  const res = await api('/api/door', { id, method, credential, zone: zoneSel });
  if (!res.ok) { setState('denied', 'ACCESS DENIED', res.message, 'bad'); beep([[220, 0.25]]); resetLater(); return; }
  showResult(res.result);
  refresh();
}

function nudge(msg, el) {
  const f = el || $('#entry'); f.classList.remove('shake'); void f.offsetWidth; f.classList.add('shake');
  $('#sub').textContent = msg;
}
const needZone = () => { if (zoneSel) return false; nudge('Choose where you want to go first', $('#zones')); return true; };

/* ---------- inputs ---------- */
$('#zones').onclick = e => {
  const b = e.target.closest('.zbtn'); if (!b) return;
  zoneSel = b.dataset.level; drawZones(); showIdle();
};

$('#entry').onsubmit = e => {
  e.preventDefault();
  if (needZone()) return;
  const id = $('#uid').value.trim(), pw = $('#pw').value;
  if (!id) { nudge('Please enter your ID'); $('#uid').focus(); return; }
  if (!pw) { nudge('Please enter your password'); $('#pw').focus(); return; }
  attempt(id, 'password', pw);
};

$('#chips').onclick = e => {
  const b = e.target.closest('.chip'); if (!b) return;
  person = S.researchers.find(r => r.id === b.dataset.id);
  document.querySelectorAll('.chip').forEach(c => c.setAttribute('aria-pressed', String(c === b)));
  $('#simhint').textContent = `Demo password for ${person.name}: ${person.name.toLowerCase()}@${person.id}`;
};

$('#tap').onclick = () => {
  if (needZone()) return;
  if (!person) { nudge('Pick who is at the door (right)'); return; }
  attempt(person.id, 'nfc', person.nfc);
};

const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
$('#finger').onclick = async () => {
  if (needZone()) return;
  if (!person) { nudge('Pick who is at the door (right)'); return; }
  if (person.fpReal && window.PublicKeyCredential) {      // real laptop fingerprint reader through Windows Hello
    try {
      setState('busy', 'Touch the sensor', 'Use the fingerprint reader', '');
      await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: 'public-key', id: unb64u(person.fingerprint.slice(3)) }],
        userVerification: 'required', timeout: 60000 } });
    } catch (err) { setState('denied', 'ACCESS DENIED', 'Fingerprint not recognised', 'bad'); beep([[220, 0.25]]); busy = true; resetLater(); return; }
  }
  attempt(person.id, 'fingerprint', person.fingerprint);
};

/* ---------- emergency button: two steps so it is never pressed by accident ---------- */
$('#sos').onclick = () => {
  if (busy) return;
  clearTimeout(resetTimer);
  const d = $('#detail'); if (d) d.remove();
  setState('sos', 'EMERGENCY', 'Raise a security alert?', 'warn');
  setButtons(true); $('#sos').disabled = true;
};
$('#sosNo').onclick = () => { setButtons(false); showIdle(); };
$('#sosYes').onclick = async () => {
  busy = true;
  const res = await api('/api/alert', { id: $('#uid').value.trim(), zone: zoneSel || '', pending: toAdmin ? '1' : '0' });
  setState('alert', 'ALERT SENT', res.ok ? (toAdmin ? 'Waiting for security' : 'Security has been notified') : res.message, 'warn');
  addDetail('Stay calm and wait for security');
  beep([[988, 0.15], [740, 0.15], [988, 0.15], [740, 0.15]]);
  resetLater();
  refresh();
};

refresh().then(() => $('#uid').focus());
setInterval(() => { if (!busy) refresh(); }, 4000);   // picks up lockdown and new researchers
