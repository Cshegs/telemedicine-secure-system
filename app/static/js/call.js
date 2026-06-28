/**
 * call.js — WebRTC video calling with hybrid ECC-Kyber session establishment.
 *
 * Call flow:
 *  1. User selects a contact → "Start Secure Call" button appears.
 *  2. On click → POST /call/start-session → server runs SPEED_PROFILE pipeline.
 *  3. Key result shown briefly (stateKeyReady), then WebRTC begins.
 *  4. Signaling via WebSocket /ws/call/{other_id} (relay of offer/answer/ICE).
 *  5. On hangup → POST /call/end → server records ended_at.
 *
 * The live audio/video stream is encrypted by WebRTC's built-in DTLS-SRTP.
 * The hybrid framework secures the call session record, not the media stream.
 */

const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

// ── State ──────────────────────────────────────────────────────────────────
let selectedOtherId   = null;
let selectedOtherName = null;
let callSessionId     = null;
let callStartTime     = null;
let signalWs          = null;
let pc                = null;        // RTCPeerConnection
let localStream       = null;
let isOfferer         = false;
let isMuted           = false;
let isVideoOff        = false;

// ── DOM refs ───────────────────────────────────────────────────────────────
const stateIdle        = document.getElementById('stateIdle');
const stateEstablishing= document.getElementById('stateEstablishing');
const stateKeyReady    = document.getElementById('stateKeyReady');
const stateInCall      = document.getElementById('stateInCall');
const stateEnded       = document.getElementById('stateEnded');
const startCallBtn     = document.getElementById('startCallBtn');
const idleTitle        = document.getElementById('idleTitle');
const remoteVideo      = document.getElementById('remoteVideo');
const localVideo       = document.getElementById('localVideo');
const remoteLabel      = document.getElementById('remoteLabel');

// ── State switching ────────────────────────────────────────────────────────
function showState(name) {
  for (const el of [stateIdle, stateEstablishing, stateKeyReady, stateInCall, stateEnded]) {
    el.classList.add('hidden');
    el.classList.remove('flex');
  }
  const target = document.getElementById('state' + name);
  target.classList.remove('hidden');
  if (['Establishing', 'KeyReady', 'Ended'].includes(name)) {
    target.classList.add('flex');
  }
}

// ── Contact selection ──────────────────────────────────────────────────────
function selectContact(otherId, otherName) {
  selectedOtherId   = otherId;
  selectedOtherName = otherName;

  // Highlight selected button
  document.querySelectorAll('.contact-btn').forEach(btn => {
    btn.classList.toggle('bg-blue-50', parseInt(btn.dataset.otherId) === otherId);
    btn.classList.toggle('border-l-2', parseInt(btn.dataset.otherId) === otherId);
    btn.classList.toggle('border-blue-600', parseInt(btn.dataset.otherId) === otherId);
  });

  idleTitle.textContent = `Call ${otherName}`;
  startCallBtn.classList.remove('hidden');
  showState('Idle');
}

// ── Step 1: Establish hybrid session key ───────────────────────────────────
async function startCall() {
  if (!selectedOtherId) return;
  showState('Establishing');

  try {
    const res = await fetch('/call/start-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ other_id: selectedOtherId }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Key establishment failed');

    callSessionId = data.call_session_id;

    // Show key result
    document.getElementById('krProfile').textContent = data.profile_name;
    document.getElementById('krWeights').textContent = `α=${data.alpha}  β=${data.beta}`;
    document.getElementById('krTime').textContent    = `${data.execution_time_ms} ms`;
    document.getElementById('krKf').textContent      = `${data.kf_preview}…`;
    document.getElementById('krSid').textContent     = data.sid.slice(0, 18) + '…';

    showState('KeyReady');

    // Brief pause so the examiner can see the timing result, then begin WebRTC
    await sleep(2000);
    await beginWebRTC();

  } catch (err) {
    console.error(err);
    showState('Idle');
    alert('Could not establish session: ' + err.message);
  }
}

// ── Step 2: WebRTC + signaling ─────────────────────────────────────────────
async function beginWebRTC() {
  showState('InCall');
  callStartTime = Date.now();
  remoteLabel.textContent = selectedOtherName;

  // Get local media
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
  } catch {
    // Camera/mic not available (e.g. in test env) — proceed without media
    localStream = null;
  }
  if (localStream) localVideo.srcObject = localStream;

  // Connect signaling socket
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  signalWs = new WebSocket(`${proto}://${location.host}/ws/call/${selectedOtherId}`);

  signalWs.onmessage = async (evt) => {
    const msg = JSON.parse(evt.data);

    if (msg.type === 'room-info') {
      // First peer in room becomes the offerer
      isOfferer = msg.peer_count === 1;
      setupPeerConnection();
      if (isOfferer) await createAndSendOffer();
      return;
    }

    if (!pc) return;

    if (msg.type === 'offer') {
      await pc.setRemoteDescription(new RTCSessionDescription(msg));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      signal({ type: 'answer', sdp: answer.sdp });

    } else if (msg.type === 'answer') {
      await pc.setRemoteDescription(new RTCSessionDescription(msg));

    } else if (msg.type === 'candidate' && msg.candidate) {
      try { await pc.addIceCandidate(new RTCIceCandidate(msg.candidate)); } catch {}

    } else if (msg.type === 'hangup') {
      endCall(false);
    }
  };

  signalWs.onerror = () => signalWs.close();
}

function setupPeerConnection() {
  pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

  if (localStream) {
    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));
  }

  pc.ontrack = (evt) => {
    remoteVideo.srcObject = evt.streams[0];
  };

  pc.onicecandidate = (evt) => {
    if (evt.candidate) signal({ type: 'candidate', candidate: evt.candidate });
  };

  pc.onconnectionstatechange = () => {
    if (['disconnected', 'failed', 'closed'].includes(pc.connectionState)) {
      endCall(false);
    }
  };
}

async function createAndSendOffer() {
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  signal({ type: 'offer', sdp: offer.sdp });
}

function signal(msg) {
  if (signalWs && signalWs.readyState === WebSocket.OPEN) {
    signalWs.send(JSON.stringify(msg));
  }
}

// ── Controls ───────────────────────────────────────────────────────────────
function toggleMute() {
  if (!localStream) return;
  isMuted = !isMuted;
  localStream.getAudioTracks().forEach(t => { t.enabled = !isMuted; });
  const btn = document.getElementById('muteBtn');
  btn.classList.toggle('bg-red-100', isMuted);
  btn.classList.toggle('bg-gray-100', !isMuted);
}

function toggleVideo() {
  if (!localStream) return;
  isVideoOff = !isVideoOff;
  localStream.getVideoTracks().forEach(t => { t.enabled = !isVideoOff; });
  const btn = document.getElementById('videoBtn');
  btn.classList.toggle('bg-red-100', isVideoOff);
  btn.classList.toggle('bg-gray-100', !isVideoOff);
}

async function hangUp() {
  signal({ type: 'hangup' });
  await endCall(true);
}

async function endCall(notifyServer = true) {
  // Stop media
  if (localStream) {
    localStream.getTracks().forEach(t => t.stop());
    localStream = null;
  }
  if (pc) { pc.close(); pc = null; }
  if (signalWs) { signalWs.close(); signalWs = null; }

  // Record end on server
  if (notifyServer && callSessionId) {
    try {
      await fetch('/call/end', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ call_session_id: callSessionId }),
      });
    } catch {}
  }

  // Show duration
  if (callStartTime) {
    const secs = Math.floor((Date.now() - callStartTime) / 1000);
    const m = Math.floor(secs / 60), s = secs % 60;
    document.getElementById('endedDuration').textContent =
      `Duration: ${m}m ${s}s`;
  }

  callSessionId = null;
  callStartTime = null;
  showState('Ended');
}

function resetToIdle() {
  showState('Idle');
}

// ── Utility ────────────────────────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
