const state = {
  eventSource: null,
  uploadedImageBase64: null,
  latestMessage: "",
  statusPoller: null,
  resultPoller: null,
};

const els = {
  messageInput: document.getElementById("messageInput"),
  imageInput: document.getElementById("imageInput"),
  uploadPreview: document.getElementById("uploadPreview"),
  transmitBtn: document.getElementById("transmitBtn"),

  senderPanel: document.getElementById("senderPanel"),
  receiverPanel: document.getElementById("receiverPanel"),
  encryptionPanel: document.getElementById("encryptionPanel"),
  stegPanel: document.getElementById("stegPanel"),
  socketPanel: document.getElementById("socketPanel"),

  receiverPlaceholder: document.getElementById("receiverPlaceholder"),
  receiverData: document.getElementById("receiverData"),
  receiverStegoImg: document.getElementById("receiverStegoImg"),

  hashExpected: document.getElementById("hashExpected"),
  hashActual: document.getElementById("hashActual"),
  hashBadge: document.getElementById("hashBadge"),
  decryptedMessage: document.getElementById("decryptedMessage"),

  plainTextValue: document.getElementById("plainTextValue"),
  rsaValue: document.getElementById("rsaValue"),
  aesValue: document.getElementById("aesValue"),
  rsaFull: document.getElementById("rsaFull"),
  aesFull: document.getElementById("aesFull"),

  boxPlain: document.getElementById("boxPlain"),
  boxRsa: document.getElementById("boxRsa"),
  boxAes: document.getElementById("boxAes"),

  originalCanvas: document.getElementById("originalCanvas"),
  stegoCanvas: document.getElementById("stegoCanvas"),
  pixelDiffBody: document.getElementById("pixelDiffBody"),

  terminalLog: document.getElementById("terminalLog"),
  progressFill: document.getElementById("progressFill"),
  progressText: document.getElementById("progressText"),
  statsRow: document.getElementById("statsRow"),
};

async function api(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`HTTP ${res.status} - ${body}`);
  }
  return res.json();
}

function setPanelActive(panel) {
  panel.classList.add("active");
}

function truncateText(value, max = 110) {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max)}...`;
}

function terminalAppend(line) {
  const div = document.createElement("div");
  div.className = "terminal-line";
  div.textContent = line;
  els.terminalLog.appendChild(div);
  els.terminalLog.scrollTop = els.terminalLog.scrollHeight;
  parseStatsLine(line);
}

function parseStatsLine(line) {
  const m1 = line.match(/(\d+) bytes sent in ([\d.]+)s \(([\d.]+) KB\/s\)/i);
  const m2 = line.match(/Transfer complete\s*-\s*(\d+) bytes in ([\d.]+)s \(([\d.]+) KB\/s\)/i);
  const m = m1 || m2;
  if (!m) return;
  els.statsRow.textContent = `${m[1]} bytes transferred · ${m[3]} KB/s · ${m[2]}s`;
}

function highlightBits(bits, changed) {
  if (!bits || bits.length !== 8) return bits || "";
  const head = bits.slice(0, 7);
  const tailClass = changed ? "lsb" : "";
  return `${head}<span class="${tailClass}">${bits.slice(7)}</span>`;
}

function renderPixelDiff(rows) {
  els.pixelDiffBody.innerHTML = "";
  if (!Array.isArray(rows) || rows.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="5">No pixel diff data yet.</td>';
    els.pixelDiffBody.appendChild(tr);
    return;
  }

  rows.forEach((row) => {
    const changed = row.original_value !== row.stego_value;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${row.pixel_index}</td>
      <td>${row.channel}</td>
      <td>${highlightBits(row.original_bits, false)}</td>
      <td>${highlightBits(row.stego_bits, changed)}</td>
      <td>${row.original_value} → ${row.stego_value}</td>
    `;
    els.pixelDiffBody.appendChild(tr);
  });
}

function animateEncryptionBoxes() {
  [els.boxPlain, els.boxRsa, els.boxAes].forEach((box) => box.classList.remove("prelit"));
  setTimeout(() => els.boxPlain.classList.add("prelit"), 100);
  setTimeout(() => els.boxRsa.classList.add("prelit"), 400);
  setTimeout(() => els.boxAes.classList.add("prelit"), 700);
}

async function drawBase64ToCanvas(base64Data, canvas) {
  if (!base64Data) return;
  const img = new Image();
  img.src = `data:image/png;base64,${base64Data}`;
  await img.decode();
  const ctx = canvas.getContext("2d");

  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const ratio = Math.min(w / img.width, h / img.height);
  const drawW = img.width * ratio;
  const drawH = img.height * ratio;
  const x = (w - drawW) / 2;
  const y = (h - drawH) / 2;
  ctx.drawImage(img, x, y, drawW, drawH);
}

async function loadOriginalCanvas() {
  try {
    const data = await api("http://127.0.0.1:5000/api/original-image");
    await drawBase64ToCanvas(data.image_base64, els.originalCanvas);
    setPanelActive(els.stegPanel);
  } catch (err) {
    terminalAppend(`[ui] original image unavailable: ${err.message}`);
  }
}

async function loadStegoCanvasAndPreview() {
  try {
    const data = await api("http://127.0.0.1:5000/api/stego-image");
    await drawBase64ToCanvas(data.image_base64, els.stegoCanvas);
    els.receiverStegoImg.src = `data:image/png;base64,${data.image_base64}`;
    setPanelActive(els.receiverPanel);
    setPanelActive(els.stegPanel);
  } catch (err) {
    terminalAppend(`[ui] stego image unavailable: ${err.message}`);
  }
}

function startEventStream() {
  if (state.eventSource) {
    state.eventSource.close();
  }

  state.eventSource = new EventSource("http://127.0.0.1:5000/api/stream");
  state.eventSource.onmessage = (event) => {
    terminalAppend(event.data);
    setPanelActive(els.socketPanel);
  };
  state.eventSource.onerror = () => {
    terminalAppend("[ui] stream disconnected; retrying via browser EventSource");
  };
}

async function pollStatusOnce() {
  const data = await api("http://127.0.0.1:5000/api/status");
  const sent = Number(data.progress?.chunks_sent || 0);
  const total = Number(data.progress?.total_chunks || 0);
  const pct = total > 0 ? Math.round((sent / total) * 100) : 0;

  els.progressFill.style.width = `${pct}%`;
  els.progressText.textContent = `Chunk ${sent}/${total} - ${pct}%`;
  if (data.pipeline_status === "running" || data.pipeline_status === "complete") {
    setPanelActive(els.socketPanel);
  }

  return data.pipeline_status;
}

function startStatusPolling() {
  if (state.statusPoller) clearInterval(state.statusPoller);

  state.statusPoller = setInterval(async () => {
    try {
      const status = await pollStatusOnce();
      if (status !== "running") {
        clearInterval(state.statusPoller);
        state.statusPoller = null;
      }
    } catch (err) {
      terminalAppend(`[ui] status poll failed: ${err.message}`);
    }
  }, 500);
}

function typewriterText(element, text) {
  element.textContent = "";
  let i = 0;
  const timer = setInterval(() => {
    element.textContent += text.charAt(i);
    i += 1;
    if (i >= text.length) clearInterval(timer);
  }, 20);
}

async function fetchAndRenderResult() {
  const data = await api("http://127.0.0.1:5000/api/result");
  if (data.status === "running") return false;

  els.receiverPlaceholder.classList.add("hidden");
  els.receiverData.classList.remove("hidden");

  els.hashExpected.textContent = data.sha256_expected || data.sha256_hash || "-";
  els.hashActual.textContent = data.sha256_actual || "-";

  const verified = data.hash_verified === true;
  els.hashBadge.textContent = verified ? "✅ VERIFIED" : "❌ TAMPERED";
  els.hashBadge.classList.toggle("ok", verified);
  els.hashBadge.classList.toggle("bad", !verified);

  typewriterText(els.decryptedMessage, data.decrypted_message || data.message || "-");

  els.plainTextValue.textContent = truncateText(state.latestMessage, 160);
  els.rsaValue.textContent = truncateText(data.rsa_ciphertext_b64);
  els.aesValue.textContent = truncateText(data.aes_ciphertext_b64);
  els.rsaFull.value = data.rsa_ciphertext_b64 || "";
  els.aesFull.value = data.aes_ciphertext_b64 || "";

  animateEncryptionBoxes();
  renderPixelDiff(data.pixel_diff || []);

  setPanelActive(els.receiverPanel);
  setPanelActive(els.encryptionPanel);
  setPanelActive(els.stegPanel);

  await loadStegoCanvasAndPreview();
  return true;
}

function startResultPolling() {
  if (state.resultPoller) clearInterval(state.resultPoller);

  state.resultPoller = setInterval(async () => {
    try {
      const done = await fetchAndRenderResult();
      if (done) {
        clearInterval(state.resultPoller);
        state.resultPoller = null;
      }
    } catch (err) {
      terminalAppend(`[ui] result poll failed: ${err.message}`);
    }
  }, 2000);
}

function bindUploadPreview() {
  els.imageInput.addEventListener("change", () => {
    const file = els.imageInput.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      state.uploadedImageBase64 = result;
      els.uploadPreview.src = result;
      els.uploadPreview.style.display = "block";
      setPanelActive(els.senderPanel);
    };
    reader.readAsDataURL(file);
  });
}

function bindCopyButtons() {
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const targetId = btn.getAttribute("data-copy-target");
      const target = document.getElementById(targetId);
      if (!target) return;

      const text = target.value !== undefined ? target.value : target.textContent;
      try {
        await navigator.clipboard.writeText(text || "");
        btn.textContent = "COPIED";
      } catch {
        btn.textContent = "FAILED";
      }
      setTimeout(() => {
        btn.textContent = "COPY";
      }, 800);
    });
  });
}

async function sendPipeline() {
  const message = els.messageInput.value.trim();
  if (!message) {
    alert("Please enter a secret message.");
    return;
  }

  state.latestMessage = message;
  els.terminalLog.innerHTML = "";
  els.statsRow.textContent = "0 bytes transferred · 0 KB/s · 0s";
  els.progressFill.style.width = "0%";
  els.progressText.textContent = "Chunk 0/0 - 0%";

  const payload = { message };
  if (state.uploadedImageBase64) payload.image_base64 = state.uploadedImageBase64;

  try {
    const started = await api("http://127.0.0.1:5000/api/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (started.status !== "started") {
      terminalAppend(`[ui] unexpected /api/send response: ${JSON.stringify(started)}`);
      return;
    }

    setPanelActive(els.senderPanel);
    startEventStream();
    startStatusPolling();
    startResultPolling();
  } catch (err) {
    terminalAppend(`[ui] send failed: ${err.message}`);
  }
}

function init() {
  bindUploadPreview();
  bindCopyButtons();
  els.transmitBtn.addEventListener("click", sendPipeline);
  startEventStream();
  loadOriginalCanvas();
}

init();
