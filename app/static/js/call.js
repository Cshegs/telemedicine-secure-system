let selectedOtherId = null;
let selectedOtherName = null;
let callSessionId = INITIAL_CALL_SESSION_ID || null;
let callStartTime = null;
let callFrame = null;
let currentRoomUrl = INITIAL_ROOM_URL || '';
let shareUrl = '';
let isMuted = false;
let isVideoOff = false;
let isEndingCall = false;

const stateIdle = document.getElementById('stateIdle');
const stateEstablishing = document.getElementById('stateEstablishing');
const stateKeyReady = document.getElementById('stateKeyReady');
const stateInCall = document.getElementById('stateInCall');
const stateEnded = document.getElementById('stateEnded');
const startCallBtn = document.getElementById('startCallBtn');
const joinCallBtn = document.getElementById('joinCallBtn');
const idleTitle = document.getElementById('idleTitle');
const remoteLabel = document.getElementById('remoteLabel');
const voiceOnlyToggle = document.getElementById('voiceOnlyToggle');
const roomSharePanel = document.getElementById('roomSharePanel');
const roomShareLink = document.getElementById('roomShareLink');
const establishingDetails = document.getElementById('establishingDetails');

function showState(name) {
  for (const el of [stateIdle, stateEstablishing, stateKeyReady, stateInCall, stateEnded]) {
    el.classList.add('hidden');
    el.classList.remove('flex');
  }

  const target = document.getElementById(`state${name}`);
  if (!target) return;
  target.classList.remove('hidden');
  target.classList.add('flex');
}

function selectContact(otherId, otherName) {
  selectedOtherId = otherId;
  selectedOtherName = otherName;

  document.querySelectorAll('.contact-btn').forEach(btn => {
    const isSelected = parseInt(btn.dataset.otherId, 10) === otherId;
    btn.classList.toggle('bg-blue-50', isSelected);
    btn.classList.toggle('border-l-2', isSelected);
    btn.classList.toggle('border-blue-600', isSelected);
  });

  idleTitle.textContent = `Call ${otherName}`;
  startCallBtn.classList.remove('hidden');
  showState('Idle');
}

async function startCall() {
  if (!selectedOtherId) return;

  showState('Establishing');
  establishingDetails.innerHTML = 'Creating a Jitsi room and deriving the session key.';

  try {
    const res = await fetch('/call/create-room', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        patient_id: selectedOtherId,
        voice_only: voiceOnlyToggle.checked,
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Room creation failed');

    callSessionId = data.call_session_id;
    currentRoomUrl = data.room_url;
    shareUrl = data.join_url || '';

    document.getElementById('krProfile').textContent = data.crypto.profile_name;
    document.getElementById('krWeights').textContent = `α=${data.crypto.alpha}  β=${data.crypto.beta}`;
    document.getElementById('krTime').textContent = `${data.crypto.execution_time_ms} ms`;
    document.getElementById('krKf').textContent = `${data.crypto.kf_preview}…`;
    document.getElementById('krSid').textContent = data.crypto.sid.slice(0, 18) + '…';
    document.getElementById('krRoomUrl').textContent = data.room_url;

    if (roomSharePanel) {
      roomSharePanel.classList.remove('hidden');
      roomShareLink.textContent = shareUrl || data.room_url;
    }

    showState('KeyReady');
    establishingDetails.innerHTML = `Kfinal derived in ${data.crypto.execution_time_ms} ms (SPEED_PROFILE α=0.7)`;

    await sleep(700);
    await joinRoom(currentRoomUrl, voiceOnlyToggle.checked);
  } catch (err) {
    console.error(err);
    showState('Idle');
    alert('Could not create room: ' + err.message);
  }
}

async function joinSharedRoom() {
  const roomUrl = currentRoomUrl || INITIAL_ROOM_URL;
  if (!roomUrl) {
    alert('No room URL available to join.');
    return;
  }

  showState('Establishing');
  establishingDetails.textContent = 'Joining the shared Jitsi room.';

  try {
    callSessionId = callSessionId || INITIAL_CALL_SESSION_ID;
    await joinRoom(roomUrl, voiceOnlyToggle.checked);
  } catch (err) {
    console.error(err);
    showState('Idle');
    alert('Could not join room: ' + err.message);
  }
}

async function joinRoom(roomUrl, startVideoOff) {
  if (!window.JitsiMeetExternalAPI) {
    throw new Error('Jitsi Meet IFrame API did not load');
  }

  showState('InCall');
  callStartTime = Date.now();
  remoteLabel.textContent = selectedOtherName || 'Patient';

  const container = document.getElementById('call-container');
  container.innerHTML = '';

  const roomName = extractJitsiRoomName(roomUrl);
  if (!roomName) {
    throw new Error('Invalid room URL');
  }

  callFrame = new JitsiMeetExternalAPI('meet.jit.si', {
    roomName,
    parentNode: container,
    width: '100%',
    height: '100%',
    configOverwrite: {
      startWithAudioMuted: false,
      startWithVideoMuted: !!startVideoOff,
    },
    interfaceConfigOverwrite: {
      SHOW_JITSI_WATERMARK: false,
      SHOW_BRAND_WATERMARK: false,
    },
  });

  callFrame.addListener('videoConferenceLeft', () => {
    if (!isEndingCall) {
      endCall(false);
    }
  });

  callFrame.addListener('readyToClose', () => {
    if (!isEndingCall) {
      endCall(false);
    }
  });

  callFrame.addListener('participantJoined', () => {
    remoteLabel.textContent = selectedOtherName || 'Participant connected';
  });

  callFrame.addListener('videoConferenceJoined', () => {
    remoteLabel.textContent = selectedOtherName || 'Connected';
  });

  isMuted = false;
  isVideoOff = !!startVideoOff;
  updateToggleButtons();
}

async function toggleMute() {
  if (!callFrame) return;
  isMuted = !isMuted;
  callFrame.executeCommand('toggleAudio');
  updateToggleButtons();
}

async function toggleVideo() {
  if (!callFrame) return;
  isVideoOff = !isVideoOff;
  callFrame.executeCommand('toggleVideo');
  updateToggleButtons();
}

function updateToggleButtons() {
  const muteBtn = document.getElementById('muteBtn');
  const videoBtn = document.getElementById('videoBtn');
  if (muteBtn) {
    muteBtn.classList.toggle('bg-red-100', isMuted);
    muteBtn.classList.toggle('bg-gray-100', !isMuted);
  }
  if (videoBtn) {
    videoBtn.classList.toggle('bg-red-100', isVideoOff);
    videoBtn.classList.toggle('bg-gray-100', !isVideoOff);
  }
}

async function hangUp() {
  isEndingCall = true;
  try {
    if (callFrame) {
      callFrame.executeCommand('hangup');
    }
  } finally {
    await endCall(true);
    isEndingCall = false;
  }
}

async function endCall(notifyServer = true) {
  if (notifyServer && callSessionId) {
    try {
      await fetch('/call/end', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ call_session_id: callSessionId }),
      });
    } catch (error) {
      console.error('Failed to persist call end:', error);
    }
  }

  if (callFrame) {
    try {
      callFrame.dispose();
    } catch (error) {
      console.error('Failed to dispose Jitsi frame:', error);
    }
    callFrame = null;
  }

  if (callStartTime) {
    const secs = Math.floor((Date.now() - callStartTime) / 1000);
    const minutes = Math.floor(secs / 60);
    const seconds = secs % 60;
    document.getElementById('endedDuration').textContent = `Duration: ${minutes}m ${seconds}s`;
  }

  callSessionId = null;
  callStartTime = null;
  currentRoomUrl = INITIAL_ROOM_URL || '';
  showState('Ended');
}

function resetToIdle() {
  showState('Idle');
}

async function copyShareLink() {
  if (!shareUrl) return;
  try {
    await navigator.clipboard.writeText(shareUrl);
  } catch {
    window.prompt('Copy the room link', shareUrl);
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function extractJitsiRoomName(roomUrl) {
  try {
    const parsed = new URL(roomUrl);
    return parsed.pathname.replace(/^\//, '').split('/')[0] || '';
  } catch {
    return '';
  }
}
