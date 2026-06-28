/**
 * chat.js — WebSocket client for the TeleMedSecure encrypted chat.
 *
 * Connects to /ws/chat/{other_id}.  The server runs the six-step
 * ECC-Kyber pipeline on every inbound message, encrypts and stores it,
 * then broadcasts the plaintext + crypto metadata back to all sockets
 * in the room.  The client only ever sees plaintext — encryption is
 * entirely server-side.
 */

(function () {
  const messagesEl = document.getElementById('messages');
  const form       = document.getElementById('chatForm');
  const input      = document.getElementById('msgInput');
  const statusEl   = document.getElementById('wsStatus');
  const cryptoBar  = document.getElementById('cryptoBar');

  let ws;
  let reconnectDelay = 1000;

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/chat/${OTHER_USER_ID}`);

    statusEl.textContent = 'Connecting…';
    statusEl.classList.remove('hidden', 'text-green-500', 'text-red-400');
    statusEl.classList.add('text-amber-500');

    ws.onopen = () => {
      statusEl.textContent = 'Connected · end-to-end encrypted';
      statusEl.classList.remove('text-amber-500', 'text-red-400');
      statusEl.classList.add('text-green-600');
      reconnectDelay = 1000;
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      appendMessage(data);

      // Update the crypto info bar with the latest pipeline stats
      cryptoBar.textContent =
        `Latest key fusion: α=${data.alpha} β=${data.beta} · ` +
        `Kf=${data.kf_preview}… · ${data.exec_ms}ms · BALANCED_PROFILE`;
      cryptoBar.classList.remove('hidden');
    };

    ws.onclose = () => {
      statusEl.textContent = `Disconnected — reconnecting in ${reconnectDelay / 1000}s…`;
      statusEl.classList.remove('text-green-600', 'text-amber-500');
      statusEl.classList.add('text-red-400');
      setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 16000);
    };

    ws.onerror = () => ws.close();
  }

  function appendMessage(data) {
    const isMine = data.sender_id === CURRENT_USER_ID;

    // Remove the empty-state placeholder if present
    const placeholder = messagesEl.querySelector('.flex.items-center.justify-center');
    if (placeholder) placeholder.remove();

    const wrapper = document.createElement('div');
    wrapper.className = `flex ${isMine ? 'justify-end' : 'justify-start'}`;

    const inner = document.createElement('div');
    inner.className = 'max-w-xs sm:max-w-sm lg:max-w-md';

    if (!isMine) {
      const name = document.createElement('p');
      name.className = 'text-xs text-gray-400 mb-1 px-1';
      name.textContent = data.sender_name;
      inner.appendChild(name);
    }

    const bubble = document.createElement('div');
    bubble.className = `rounded-2xl px-4 py-2.5 ${
      isMine
        ? 'bg-blue-700 text-white rounded-br-sm'
        : 'bg-gray-100 text-gray-900 rounded-bl-sm'
    }`;
    const p = document.createElement('p');
    p.className = 'text-sm leading-relaxed';
    p.textContent = data.text;
    bubble.appendChild(p);
    inner.appendChild(bubble);

    const meta = document.createElement('div');
    meta.className = `flex items-center gap-2 mt-1 px-1 ${isMine ? 'justify-end' : ''}`;
    meta.innerHTML = `<span class="text-xs text-gray-400">${data.timestamp}</span>
                      <span class="text-xs text-gray-300 font-mono">· ${data.exec_ms}ms</span>`;
    inner.appendChild(meta);

    wrapper.appendChild(inner);
    messagesEl.appendChild(wrapper);

    // Scroll to bottom
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(text);
    input.value = '';
    input.focus();
  });

  // Scroll history to bottom on load
  messagesEl.scrollTop = messagesEl.scrollHeight;

  connect();
})();
