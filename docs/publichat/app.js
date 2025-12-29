// ============================================================
// PucliChat Client (WebSocket signaling + WebRTC DataChannel)
// - Match with password (server sees only roomKeyHash)
// - TURN REST credentials delivered after match
// - E2E: ECDH(P-521) + HKDF(SHA-256) -> AES-GCM
// - Text + File attachment (chunked, AES-GCM per-file key)
// ============================================================

const $ = (id) => document.getElementById(id);

const UI = {
  status: $("status"),
  password: $("password"),
  wsUrl: $("wsUrl"),
  turnHost: $("turnHost"),
  btnJoin: $("btnJoin"),
  btnLeave: $("btnLeave"),
  roomInfo: $("roomInfo"),
  roleInfo: $("roleInfo"),
  sas: $("sas"),
  log: $("log"),
  msgs: $("msgs"),
  text: $("text"),
  btnSend: $("btnSend"),
  file: $("file"),
  btnSendFile: $("btnSendFile"),
  progBar: $("progBar"),
  progText: $("progText"),
};

function logLine(s) {
  UI.log.textContent += (UI.log.textContent ? "\n" : "") + s;
  UI.log.scrollTop = UI.log.scrollHeight;
  console.log(s);
}

function addMsg(who, text) {
  const div = document.createElement("div");
  div.className = "msg";
  div.innerHTML = `<span class="${who}">${who.toUpperCase()}</span> <span class="muted">${new Date().toLocaleTimeString()}</span><br/>${escapeHtml(text)}`;
  UI.msgs.appendChild(div);
  UI.msgs.scrollTop = UI.msgs.scrollHeight;
}
function addSys(text) { addMsg("sys", text); }

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;" }[c]));
}

// ----------------------- crypto helpers -----------------------
const te = new TextEncoder();
const td = new TextDecoder();

function u8cat(...parts) {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function b64urlEncode(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecode(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
async function sha256Bytes(data) {
  const buf = data instanceof ArrayBuffer ? data : data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(hash);
}
async function hkdf(ikmU8, saltU8, infoStr, length) {
  const key = await crypto.subtle.importKey("raw", ikmU8, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: saltU8, info: te.encode(infoStr) },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}
function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}
function readU32LE(dv, off) { return dv.getUint32(off, true) >>> 0; }

// ----------------------- protocol constants -----------------------
const VER = 1;
const MSG_TEXT = 1;
const MSG_FILE_CHUNK = 2;

// ----------------------- file transfer defaults -----------------------
const DEFAULTS = {
  MAX_FILE_BYTES: 100 * 1024 * 1024, // 100MB
  CHUNK_SIZE: 32 * 1024,             // 32KB
  BUFFER_HIGH_WATER: 4 * 1024 * 1024,// 4MB
  BUFFER_LOW_TH: 1 * 1024 * 1024     // 1MB
};

// incoming/outgoing maps
const incoming = Object.create(null);
const outgoing = Object.create(null);

function setProgress(pct, text) {
  UI.progBar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
  UI.progText.textContent = text || "-";
}

// ----------------------- state -----------------------
let ws = null;
let roomId = null;
let role = null; // offerer/answerer
let iceServers = null;

let pc = null;
let dc = null;

let pwHash = null;        // Uint8Array(32)
let sessionKeyRaw = null; // Uint8Array(32) - established after keyInit
let myECDH = null;        // CryptoKeyPair (ECDH)
let peerPubRaw = null;    // Uint8Array
let sasCode = "-";

// ----------------------- AAD builders -----------------------
function aadText(ver, type, seq) {
  // AAD = ver(1)|type(1)|seq(u32)
  return u8cat(new Uint8Array([ver & 0xff, type & 0xff]), u32le(seq));
}
function aadFileChunk(ver, type, fileIdRaw16, index, totalChunks) {
  return u8cat(new Uint8Array([ver & 0xff, type & 0xff]), fileIdRaw16, u32le(index), u32le(totalChunks));
}

// ----------------------- pack/unpack text -----------------------
// Binary frame: ver(1)|type(1=MSG_TEXT)|seq(u32)|iv(12)|ctLen(u32)|ct
function packTextFrame(seq, iv12, ctU8) {
  const headerLen = 1 + 1 + 4 + 12 + 4;
  const out = new Uint8Array(headerLen + ctU8.length);
  let off = 0;
  out[off++] = VER;
  out[off++] = MSG_TEXT;
  out.set(u32le(seq), off); off += 4;
  out.set(iv12, off); off += 12;
  out.set(u32le(ctU8.length), off); off += 4;
  out.set(ctU8, off);
  return out.buffer;
}
function unpackTextFrame(buf) {
  const u8 = new Uint8Array(buf);
  const dv = new DataView(buf);
  let off = 0;
  const ver = u8[off++], type = u8[off++];
  if (ver !== VER || type !== MSG_TEXT) throw new Error("not text frame");
  const seq = readU32LE(dv, off); off += 4;
  const iv12 = u8.slice(off, off + 12); off += 12;
  const ctLen = readU32LE(dv, off); off += 4;
  if (off + ctLen > u8.length) throw new Error("invalid ctLen");
  const ct = u8.slice(off, off + ctLen);
  return { seq, iv12, ct };
}

// ----------------------- pack/unpack fileChunk -----------------------
// Binary frame: ver(1)|type(2)|fileId(16)|index(u32)|total(u32)|iv(12)|ctLen(u32)|ct
function packFileChunkFrame(fileIdRaw16, index, totalChunks, iv12, ctU8) {
  const headerLen = 1 + 1 + 16 + 4 + 4 + 12 + 4;
  const out = new Uint8Array(headerLen + ctU8.length);
  let off = 0;
  out[off++] = VER;
  out[off++] = MSG_FILE_CHUNK;
  out.set(fileIdRaw16, off); off += 16;
  out.set(u32le(index), off); off += 4;
  out.set(u32le(totalChunks), off); off += 4;
  out.set(iv12, off); off += 12;
  out.set(u32le(ctU8.length), off); off += 4;
  out.set(ctU8, off);
  return out.buffer;
}
function unpackFileChunkFrame(buf) {
  const u8 = new Uint8Array(buf);
  const dv = new DataView(buf);
  let off = 0;
  const ver = u8[off++], type = u8[off++];
  if (ver !== VER || type !== MSG_FILE_CHUNK) throw new Error("not fileChunk");
  const fileIdRaw16 = u8.slice(off, off + 16); off += 16;
  const index = readU32LE(dv, off); off += 4;
  const totalChunks = readU32LE(dv, off); off += 4;
  const iv12 = u8.slice(off, off + 12); off += 12;
  const ctLen = readU32LE(dv, off); off += 4;
  if (off + ctLen > u8.length) throw new Error("invalid ctLen");
  const ct = u8.slice(off, off + ctLen);
  return { fileIdRaw16, index, totalChunks, iv12, ct };
}

// ----------------------- backpressure -----------------------
function waitBufferedLow(dc, highWater = DEFAULTS.BUFFER_HIGH_WATER) {
  if (dc.bufferedAmount <= highWater) return Promise.resolve();
  return new Promise((resolve) => {
    const onLow = () => { dc.removeEventListener("bufferedamountlow", onLow); resolve(); };
    dc.addEventListener("bufferedamountlow", onLow);
  });
}

// ----------------------- E2E handshake -----------------------
async function genECDH() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveBits"]);
}
async function exportPubRaw(keyPair) {
  const raw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  return new Uint8Array(raw);
}
async function importPeerPubRaw(rawU8) {
  return crypto.subtle.importKey("raw", rawU8, { name: "ECDH", namedCurve: "P-521" }, true, []);
}
async function deriveSessionKey(myPrivKey, peerPubKey, saltU8) {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerPubKey }, myPrivKey, 528); // P-521 bits
  const shared = new Uint8Array(bits);
  // HKDF -> 32 bytes
  return hkdf(shared, saltU8, "puclichat-chat-key-v1", 32);
}
async function makeSAS(pubA, pubB, saltU8) {
  // SAS = short code from SHA256(pubA||pubB||salt)
  // pub order: sort lexicographically to get same result
  const a = b64urlEncode(pubA), b = b64urlEncode(pubB);
  const [x, y] = a < b ? [pubA, pubB] : [pubB, pubA];
  const h = await sha256Bytes(u8cat(x, y, saltU8));
  // 6桁x2（簡易）
  const dv = new DataView(h.buffer);
  const n1 = dv.getUint32(0, true) % 1000000;
  const n2 = dv.getUint32(4, true) % 1000000;
  return `${String(n1).padStart(6,"0")}-${String(n2).padStart(6,"0")}`;
}

// ----------------------- JSON control send/recv -----------------------
function wsSend(obj) {
  ws?.send(JSON.stringify(obj));
}
function dcSendJson(obj) {
  dc?.send(JSON.stringify(obj));
}
function isJsonLike(s) {
  const t = s.trim();
  return t.startsWith("{") && t.endsWith("}");
}

// ----------------------- file helpers -----------------------
function createFileId() {
  const raw = crypto.getRandomValues(new Uint8Array(16));
  return { raw, b64: b64urlEncode(raw) };
}
async function sha256File(file) {
  const buf = await file.arrayBuffer();
  return sha256Bytes(buf);
}
async function deriveFileAesKey(sessionKeyRaw, fileIdRaw16) {
  const fileKeyRaw = await hkdf(sessionKeyRaw, fileIdRaw16, "puclichat-file-key-v1", 32);
  return crypto.subtle.importKey("raw", fileKeyRaw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

// ----------------------- chat send/recv -----------------------
let sendSeq = 0;

async function sendTextMessage(text) {
  if (!sessionKeyRaw) throw new Error("no session key");
  const aesKey = await crypto.subtle.importKey("raw", sessionKeyRaw, "AES-GCM", false, ["encrypt"]);

  const seq = ++sendSeq;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = aadText(VER, MSG_TEXT, seq);
  const pt = te.encode(text);
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, aesKey, pt);
  const frame = packTextFrame(seq, iv, new Uint8Array(ctBuf));
  dc.send(frame);

  addMsg("me", text);
}

async function handleTextFrame(buf) {
  if (!sessionKeyRaw) return;
  const aesKey = await crypto.subtle.importKey("raw", sessionKeyRaw, "AES-GCM", false, ["decrypt"]);

  const { seq, iv12, ct } = unpackTextFrame(buf);
  const aad = aadText(VER, MSG_TEXT, seq);
  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv12, additionalData: aad },
    aesKey,
    ct.buffer.slice(ct.byteOffset, ct.byteOffset + ct.byteLength)
  );
  addMsg("peer", td.decode(new Uint8Array(ptBuf)));
}

// ----------------------- file send/recv -----------------------
async function sendFileOffer(file) {
  if (!sessionKeyRaw) throw new Error("no session key");
  if (file.size > DEFAULTS.MAX_FILE_BYTES) throw new Error("file too large");

  const { raw: fileIdRaw16, b64: fileId } = createFileId();
  setProgress(1, "ハッシュ計算中…");
  const sha = await sha256File(file);
  const chunkSize = DEFAULTS.CHUNK_SIZE;
  const totalChunks = Math.ceil(file.size / chunkSize);

  const offer = {
    t: "fileOffer",
    fileId,
    name: file.name || "file",
    mime: file.type || "application/octet-stream",
    size: file.size >>> 0,
    chunkSize,
    totalChunks,
    sha256: b64urlEncode(sha),
  };

  const fileKey = await deriveFileAesKey(sessionKeyRaw, fileIdRaw16);
  outgoing[fileId] = { offer, fileIdRaw16, fileKey, file, sent: 0 };

  dcSendJson(offer);
  addSys(`ファイル提案: ${offer.name} (${Math.round(offer.size/1024)}KB)`);
  setProgress(2, "相手の許可待ち…");
}

async function startSendFile(fileId) {
  const st = outgoing[fileId];
  if (!st) return;
  const { offer, fileIdRaw16, fileKey, file } = st;

  for (let index = 0; index < offer.totalChunks; index++) {
    await waitBufferedLow(dc);

    const start = index * offer.chunkSize;
    const end = Math.min(file.size, start + offer.chunkSize);
    const plain = await file.slice(start, end).arrayBuffer();

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = aadFileChunk(VER, MSG_FILE_CHUNK, fileIdRaw16, index, offer.totalChunks);
    const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, fileKey, plain);
    const frame = packFileChunkFrame(fileIdRaw16, index, offer.totalChunks, iv, new Uint8Array(ctBuf));

    dc.send(frame);
    st.sent = index + 1;

    const pct = Math.floor((st.sent / offer.totalChunks) * 100);
    setProgress(pct, `送信中: ${offer.name} ${st.sent}/${offer.totalChunks}`);
  }

  dcSendJson({ t: "fileDone", fileId, totalChunks: offer.totalChunks, sha256: offer.sha256 });
  addSys(`ファイル送信完了: ${offer.name}`);
  setProgress(100, `送信完了: ${offer.name}`);
  // 後始末
  setTimeout(() => { delete outgoing[fileId]; setProgress(0, "-"); }, 1500);
}

async function acceptFile(offer) {
  const fileIdRaw16 = b64urlDecode(offer.fileId);
  const fileKey = await deriveFileAesKey(sessionKeyRaw, fileIdRaw16);
  incoming[offer.fileId] = {
    offer,
    fileIdRaw16,
    fileKey,
    chunks: new Array(offer.totalChunks),
    recv: 0
  };
  dcSendJson({ t: "fileAccept", fileId: offer.fileId });
  addSys(`受信許可: ${offer.name}`);
}
function rejectFile(offer, reason) {
  dcSendJson({ t: "fileReject", fileId: offer.fileId, reason: reason || "user_declined" });
  addSys(`受信拒否: ${offer.name}`);
}

async function handleFileChunk(buf) {
  const { fileIdRaw16, index, totalChunks, iv12, ct } = unpackFileChunkFrame(buf);
  const fileId = b64urlEncode(fileIdRaw16);
  const st = incoming[fileId];
  if (!st) return;

  if (st.offer.totalChunks !== totalChunks) {
    delete incoming[fileId];
    throw new Error("totalChunks mismatch");
  }
  if (index >= totalChunks) throw new Error("index out of range");
  if (st.chunks[index]) return;

  const aad = aadFileChunk(VER, MSG_FILE_CHUNK, fileIdRaw16, index, totalChunks);
  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv12, additionalData: aad },
    st.fileKey,
    ct.buffer.slice(ct.byteOffset, ct.byteOffset + ct.byteLength)
  );

  st.chunks[index] = new Uint8Array(ptBuf);
  st.recv++;

  const pct = Math.floor((st.recv / totalChunks) * 100);
  setProgress(pct, `受信中: ${st.offer.name} ${st.recv}/${totalChunks}`);

  if (st.recv === totalChunks) {
    const blob = new Blob(st.chunks, { type: st.offer.mime || "application/octet-stream" });
    const buf2 = await blob.arrayBuffer();
    const hash = await sha256Bytes(buf2);
    const hashB64 = b64urlEncode(hash);

    if (hashB64 !== st.offer.sha256) {
      delete incoming[fileId];
      setProgress(0, "-");
      addSys(`受信失敗（ハッシュ不一致）: ${st.offer.name}`);
      return;
    }

    // ダウンロード
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = st.offer.name || "download";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 30_000);

    addSys(`受信完了: ${st.offer.name}`);
    delete incoming[fileId];
    setProgress(100, `受信完了: ${st.offer.name}`);
    setTimeout(() => setProgress(0, "-"), 1500);
  }
}

// ----------------------- WebRTC -----------------------
function makePeerConnection(iceServers) {
  const pc = new RTCPeerConnection({
    iceServers,
    iceTransportPolicy: "all"
  });
  return pc;
}

function setupDataChannelHandlers(dc) {
  dc.binaryType = "arraybuffer";
  dc.bufferedAmountLowThreshold = DEFAULTS.BUFFER_LOW_TH;

  dc.onopen = async () => {
    addSys("DataChannel open");
    UI.btnSend.disabled = false;
    UI.btnSendFile.disabled = false;

    // E2E handshake: keyInit exchange over DataChannel
    // - derive authKey from pwHash + roomId
    // - attach HMAC to pubkey to mitigate MITM
    myECDH = await genECDH();
    const myPub = await exportPubRaw(myECDH);

    const salt = te.encode(roomId);
    const authKeyRaw = await hkdf(pwHash, salt, "puclichat-auth-v1", 32);
    const hmacKey = await crypto.subtle.importKey("raw", authKeyRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const payload = u8cat(te.encode("keyInit|"), myPub, te.encode("|"), nonce, te.encode("|"), salt);
    const macBuf = await crypto.subtle.sign("HMAC", hmacKey, payload);
    const msg = {
      t: "keyInit",
      pub: b64urlEncode(myPub),
      nonce: b64urlEncode(nonce),
      mac: b64urlEncode(new Uint8Array(macBuf))
    };
    dcSendJson(msg);
    addSys("keyInit sent");
  };

  dc.onmessage = async (ev) => {
    try {
      if (typeof ev.data === "string") {
        if (!isJsonLike(ev.data)) return;
        const msg = JSON.parse(ev.data);

        if (msg.t === "keyInit") {
          // verify HMAC with authKey
          const salt = te.encode(roomId);
          const authKeyRaw = await hkdf(pwHash, salt, "puclichat-auth-v1", 32);
          const hmacKey = await crypto.subtle.importKey("raw", authKeyRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

          const peerPub = b64urlDecode(msg.pub);
          const nonce = b64urlDecode(msg.nonce);
          const mac = b64urlDecode(msg.mac);

          const payload = u8cat(te.encode("keyInit|"), peerPub, te.encode("|"), nonce, te.encode("|"), salt);
          const ok = await crypto.subtle.verify("HMAC", hmacKey, mac, payload);

          if (!ok) {
            addSys("keyInit HMAC verify failed → disconnect");
            dc.close();
            pc?.close();
            return;
          }

          peerPubRaw = peerPub;
          addSys("keyInit verified");

          // derive session key if we already have my keypair
          if (!myECDH) myECDH = await genECDH();
          const peerPubKey = await importPeerPubRaw(peerPubRaw);
          const sk = await deriveSessionKey(myECDH.privateKey, peerPubKey, te.encode(roomId));
          sessionKeyRaw = sk;

          sasCode = await makeSAS(await exportPubRaw(myECDH), peerPubRaw, te.encode(roomId));
          UI.sas.textContent = sasCode;
          addSys(`E2E established. SAS=${sasCode}`);
          return;
        }

        // file control
        if (msg.t === "fileOffer") {
          const sizeOk = msg.size <= DEFAULTS.MAX_FILE_BYTES;
          if (!sizeOk) {
            rejectFile(msg, "too_large");
            return;
          }
          const ok = confirm(`ファイル受信\n${msg.name}\n${Math.round(msg.size/1024)}KB\n受信しますか？`);
          if (!ok) { rejectFile(msg, "user_declined"); return; }
          await acceptFile(msg);
          return;
        }
        if (msg.t === "fileAccept") {
          await startSendFile(msg.fileId);
          return;
        }
        if (msg.t === "fileReject") {
          addSys(`相手が拒否: ${msg.fileId} (${msg.reason || ""})`);
          delete outgoing[msg.fileId];
          setProgress(0, "-");
          return;
        }
        if (msg.t === "fileDone") {
          // 最小構成では揃い次第完了するのでここは通知用途
          return;
        }
        return;
      }

      if (ev.data instanceof ArrayBuffer) {
        // binary frames: text or fileChunk
        const u8 = new Uint8Array(ev.data);
        if (u8.length < 2) return;
        const ver = u8[0], type = u8[1];
        if (ver !== VER) return;

        if (type === MSG_TEXT) {
          await handleTextFrame(ev.data);
          return;
        }
        if (type === MSG_FILE_CHUNK) {
          await handleFileChunk(ev.data);
          return;
        }
      }
    } catch (e) {
      console.error(e);
      addSys(`受信エラー: ${String(e?.message || e)}`);
    }
  };

  dc.onclose = () => {
    addSys("DataChannel closed");
    UI.btnSend.disabled = true;
    UI.btnSendFile.disabled = true;
  };
}

async function startWebRTCAsOfferer() {
  pc = makePeerConnection(iceServers);
  pc.onicecandidate = (e) => {
    if (e.candidate) wsSend({ type: "signal", roomId, signalType: "ice", payload: e.candidate });
  };

  dc = pc.createDataChannel("chat", { ordered: true }); // reliable
  setupDataChannelHandlers(dc);

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  wsSend({ type: "signal", roomId, signalType: "offer", payload: offer });
  addSys("offer sent");
}

async function startWebRTCAsAnswerer() {
  pc = makePeerConnection(iceServers);
  pc.ondatachannel = (ev) => {
    dc = ev.channel;
    setupDataChannelHandlers(dc);
  };
  pc.onicecandidate = (e) => {
    if (e.candidate) wsSend({ type: "signal", roomId, signalType: "ice", payload: e.candidate });
  };
}

async function handleSignal(signalType, payload) {
  if (!pc) return;

  if (signalType === "offer") {
    await pc.setRemoteDescription(payload);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    wsSend({ type: "signal", roomId, signalType: "answer", payload: answer });
    addSys("answer sent");
    return;
  }
  if (signalType === "answer") {
    await pc.setRemoteDescription(payload);
    addSys("answer received");
    return;
  }
  if (signalType === "ice") {
    try {
      await pc.addIceCandidate(payload);
    } catch (e) {
      console.warn("addIceCandidate failed", e);
    }
    return;
  }
}

// ----------------------- WebSocket signaling -----------------------
async function normalizePassword(pw) {
  return (pw || "").trim().normalize("NFC");
}

async function computeRoomKeyHash(password) {
  // pwHash = SHA256(normalized pw)
  const pwU8 = te.encode(password);
  pwHash = await sha256Bytes(pwU8);

  // roomKey = HKDF(pwHash, salt="PucliChat", info="match-v1", len=32)
  const salt = te.encode("PucliChat");
  const roomKey = await hkdf(pwHash, salt, "match-v1", 32);

  // roomKeyHash = SHA256(roomKey)
  const roomKeyHash = await sha256Bytes(roomKey);
  return b64urlEncode(roomKeyHash);
}

function setConnectedUI(connected) {
  UI.btnJoin.disabled = connected;
  UI.btnLeave.disabled = !connected;
  UI.btnSend.disabled = !connected || !dc || dc.readyState !== "open" || !sessionKeyRaw;
  UI.btnSendFile.disabled = !connected || !dc || dc.readyState !== "open" || !sessionKeyRaw;
}

function setStatus(text) {
  UI.status.textContent = text;
}

function cleanupAll() {
  try { ws?.close(); } catch {}
  ws = null;

  try { dc?.close(); } catch {}
  dc = null;

  try { pc?.close(); } catch {}
  pc = null;

  roomId = null;
  role = null;
  iceServers = null;

  sessionKeyRaw = null;
  myECDH = null;
  peerPubRaw = null;
  UI.sas.textContent = "-";
  sasCode = "-";

  UI.roomInfo.textContent = "room:-";
  UI.roleInfo.textContent = "-";
  setProgress(0, "-");
  setStatus("DISCONNECTED");
  setConnectedUI(false);
}

async function join() {
  const wsUrl = UI.wsUrl.value.trim();
  const turnHost = UI.turnHost.value.trim();
  const pw = await normalizePassword(UI.password.value);

  if (!wsUrl) { alert("WebSocket URLを入れてください"); return; }
  if (!turnHost) { alert("TURNドメインを入れてください"); return; }
  if (!pw) { alert("合言葉を入れてください"); return; }

  const roomKeyHash = await computeRoomKeyHash(pw);

  cleanupAll();
  setStatus("CONNECTING…");

  ws = new WebSocket(wsUrl);
  ws.onopen = () => {
    setStatus("WS CONNECTED");
    wsSend({ type: "join", roomKeyHash, clientHello: b64urlEncode(crypto.getRandomValues(new Uint8Array(16))), cap: { webrtc: true, turn: true, proto: 1 }, turnHost });
    addSys("join sent");
    setConnectedUI(true);
  };

  ws.onmessage = async (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }

    if (msg.type === "waiting") {
      addSys(`待機中（残り ${msg.expiresInSec}s）`);
      return;
    }

    if (msg.type === "matched") {
      roomId = msg.roomId;
      role = msg.role;
      UI.roomInfo.textContent = `room:${roomId}`;
      UI.roleInfo.textContent = role;
      addSys(`マッチ成立 room=${roomId} role=${role}`);
      return;
    }

    if (msg.type === "turnCred") {
      // iceServers from server; also include user-provided host as fallback
      iceServers = msg.iceServers;
      addSys("TURN資格情報 受領");

      // start PC based on role
      if (role === "offerer") {
        await startWebRTCAsOfferer();
      } else {
        await startWebRTCAsAnswerer();
      }
      return;
    }

    if (msg.type === "signal") {
      if (!pc) return;
      await handleSignal(msg.signalType, msg.payload);
      return;
    }

    if (msg.type === "peerLeft") {
      addSys("相手が退出しました");
      cleanupAll();
      return;
    }

    if (msg.type === "timeout") {
      addSys("タイムアウト（10分）");
      cleanupAll();
      return;
    }

    if (msg.type === "error") {
      addSys(`サーバーエラー: ${msg.code || ""} ${msg.message || ""}`);
      return;
    }
  };

  ws.onclose = () => {
    addSys("WS closed");
    cleanupAll();
  };
  ws.onerror = () => {
    addSys("WS error");
  };
}

function leave() {
  try { wsSend({ type: "leave", roomId }); } catch {}
  cleanupAll();
}

// ----------------------- UI wiring -----------------------
UI.btnJoin.onclick = () => join().catch((e) => { console.error(e); alert(String(e?.message || e)); });
UI.btnLeave.onclick = () => leave();

UI.btnSend.onclick = () => {
  const t = UI.text.value.trim();
  if (!t) return;
  UI.text.value = "";
  sendTextMessage(t).catch((e) => addSys(`送信失敗: ${String(e?.message || e)}`));
};

UI.text.addEventListener("keydown", (e) => {
  if (e.key === "Enter") UI.btnSend.click();
});

UI.btnSendFile.onclick = () => {
  const f = UI.file.files?.[0];
  if (!f) { alert("ファイルを選択してください"); return; }
  sendFileOffer(f).catch((e) => addSys(`ファイル送信失敗: ${String(e?.message || e)}`));
};

cleanupAll();
logLine("PucliChat ready.");
