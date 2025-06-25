// --- 定数定義 ---
const EC_CURVE = "P-521";
const AES_ALGORITHM = "AES-GCM";
const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12;

// --- グローバル変数 ---
let db;
const logicalKeys = {}; // { keyName: { enc: {publicKey,privateKey,...}, sign: {publicKey,privateKey,...} } }
const importedPrivateKeys = [];
const encryptionPublicKeys = [];
const filesToProcess = [];

// --- IndexedDB ---
function initDB() {
  const request = indexedDB.open("PubliCryptDB2", 1);
  request.onupgradeneeded = function(e) {
    db = e.target.result;
    if (!db.objectStoreNames.contains("keys")) {
      db.createObjectStore("keys", { keyPath: "logicalName" });
    }
  };
  request.onsuccess = function(e) {
    db = e.target.result;
    loadKeysFromDB();
  };
  request.onerror = function(e) {
    console.error("IndexedDB error", e);
  };
}
async function storeLogicalKey(logicalName, obj) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const rec = {
      logicalName,
      encPublicJwk: obj.encPublicJwk, encPrivateJwk: obj.encPrivateJwk,
      signPublicJwk: obj.signPublicJwk, signPrivateJwk: obj.signPrivateJwk,
      curve: obj.curve
    };
    const req = store.put(rec);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e);
  });
}
async function loadKeysFromDB() {
  const transaction = db.transaction("keys", "readonly");
  const store = transaction.objectStore("keys");
  const req = store.getAll();
  req.onsuccess = async function() {
    const records = req.result;
    for (const record of records) {
      logicalKeys[record.logicalName] = {};
      logicalKeys[record.logicalName].curve = record.curve || EC_CURVE;
      // 暗号化(ECDH)
      const encPub = await crypto.subtle.importKey(
        "jwk", record.encPublicJwk, {name:"ECDH", namedCurve:record.curve||EC_CURVE}, true, []
      );
      const encPriv = await crypto.subtle.importKey(
        "jwk", record.encPrivateJwk, {name:"ECDH", namedCurve:record.curve||EC_CURVE}, true, ["deriveKey"]
      );
      logicalKeys[record.logicalName].enc = {publicKey:encPub, privateKey:encPriv, curve:record.curve||EC_CURVE};
      // 署名(ECDSA)
      const signPub = await crypto.subtle.importKey(
        "jwk", record.signPublicJwk, {name:"ECDSA", namedCurve:record.curve||EC_CURVE}, true, ["verify"]
      );
      const signPriv = await crypto.subtle.importKey(
        "jwk", record.signPrivateJwk, {name:"ECDSA", namedCurve:record.curve||EC_CURVE}, true, ["sign"]
      );
      logicalKeys[record.logicalName].sign = {publicKey:signPub, privateKey:signPriv, curve:record.curve||EC_CURVE};
    }
    refreshKeyList();
  }
}

// --- ユーティリティ ---
function base64ToBase64Url(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64UrlToBase64(url) {
  let b64 = url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) { b64 += '='; }
  return b64;
}
function arrayBufferToBase64(buffer) {
  let binary = '';
  let bytes = (buffer instanceof Uint8Array) ? buffer : new Uint8Array(buffer);
  for (let b of bytes) { binary += String.fromCharCode(b); }
  return btoa(binary);
}
function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
  return bytes;
}
function concatUint8Arrays(arrays) {
  let total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  let result = new Uint8Array(total);
  let offset = 0;
  arrays.forEach(arr => { result.set(arr, offset); offset += arr.length; });
  return result;
}
function writeInt32LE(val) {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setInt32(0, val, true);
  return new Uint8Array(buf);
}
function readInt32LE(view, offset) {
  return view.getInt32(offset, true);
}

// --- XML形式変換 ---
function convertPublicJwkToXml(jwk, usage) {
  if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y><Usage>${usage}</Usage></ECKeyValue>`;
  }
}
function convertPrivateJwkToXml(jwk, usage) {
  if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y><D>${jwk.d}</D><Usage>${usage}</Usage></ECKeyValue>`;
  }
}

// --- UI補助 ---
function showSpinner() { document.getElementById('spinner').style.display = 'block'; }
function hideSpinner() { document.getElementById('spinner').style.display = 'none'; }
function clearExportArea() { document.getElementById("exportArea").innerHTML = ""; }
function resetUI() {
  filesToProcess.length = 0;
  document.getElementById('fileList').innerHTML = "";
  document.getElementById('fileDropArea').textContent = "ここにファイルをドロップ";
  document.getElementById('pubKeyList').innerHTML = "";
  document.getElementById('fileSelect').value = "";
  document.getElementById('privKeyList').innerHTML = "";
  hideSpinner();
  const pubkeyFileSelectBlock = document.getElementById('pubkey-file-select-block');
  if (pubkeyFileSelectBlock) pubkeyFileSelectBlock.style.display = "";
  const signInfo = document.getElementById("pubkey-sign-info");
  if (signInfo) signInfo.innerHTML = "";
}

// --- 鍵生成：自動でECDH+ECDSA両方 ---
async function generateLogicalKeyPair(name) {
  const encKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: EC_CURVE },
    true, ["deriveKey", "deriveBits"]
  );
  const signKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: EC_CURVE },
    true, ["sign", "verify"]
  );
  logicalKeys[name] = {
    enc: encKeyPair,
    sign: signKeyPair,
    curve: EC_CURVE
  };
  const encPublicJwk = await crypto.subtle.exportKey("jwk", encKeyPair.publicKey);
  const encPrivateJwk = await crypto.subtle.exportKey("jwk", encKeyPair.privateKey);
  const signPublicJwk = await crypto.subtle.exportKey("jwk", signKeyPair.publicKey);
  const signPrivateJwk = await crypto.subtle.exportKey("jwk", signKeyPair.privateKey);
  await storeLogicalKey(name, {encPublicJwk,encPrivateJwk,signPublicJwk,signPrivateJwk,curve:EC_CURVE});
  alert("鍵ペア生成完了: " + name);
  refreshKeyList();
  resetUI();
}

// --- 鍵一覧UI ---
function refreshKeyList() {
  const tbody = document.getElementById("keyTable").querySelector("tbody");
  tbody.innerHTML = "";
  for (const name in logicalKeys) {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.textContent = name;
    tr.appendChild(tdName);
    const tdInfo = document.createElement("td");
    tdInfo.innerHTML = "暗号化(ECDH)+署名(ECDSA)<br>Curve:" + (logicalKeys[name].curve||EC_CURVE);
    tr.appendChild(tdInfo);
    const tdOps = document.createElement("td");
    const exportPubBtn = document.createElement("button");
    exportPubBtn.textContent = "公開鍵エクスポート";
    exportPubBtn.onclick = () => exportKey(name, "public");
    const exportPubUrlBtn = document.createElement("button");
    exportPubUrlBtn.textContent = "公開鍵URL共有";
    exportPubUrlBtn.onclick = () => exportPubkeyUrl(name);
    const exportPubUrlSignBtn = document.createElement("button");
    exportPubUrlSignBtn.textContent = "署名付きURL共有";
    exportPubUrlSignBtn.onclick = () => exportPubkeyUrlWithSign(name);
    const exportPrivBtn = document.createElement("button");
    exportPrivBtn.textContent = "秘密鍵エクスポート";
    exportPrivBtn.onclick = () => exportKey(name, "private");
    const deleteBtn = document.createElement("button");
    deleteBtn.textContent = "削除";
    deleteBtn.onclick = () => deleteKey(name);

    tdOps.appendChild(exportPubBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(exportPubUrlBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(exportPubUrlSignBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(exportPrivBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(deleteBtn);

    tr.appendChild(tdOps);
    tbody.appendChild(tr);
  }
}

// --- エクスポート/インポート/削除 ---
async function exportKey(name, type) {
  const keyObj = logicalKeys[name];
  if (!keyObj) { alert("鍵が存在しません"); return; }
  let xml = "";
  if (type === "public") {
    const encJwk = await crypto.subtle.exportKey("jwk", keyObj.enc.publicKey);
    const signJwk = await crypto.subtle.exportKey("jwk", keyObj.sign.publicKey);
    xml = 
      "-----BEGIN EC PUBLIC KEY FOR ENCRYPTION-----\n" +
      convertPublicJwkToXml(encJwk, "encryption") + "\n" +
      "-----END EC PUBLIC KEY FOR ENCRYPTION-----\n" +
      "-----BEGIN EC PUBLIC KEY FOR SIGNATURE-----\n" +
      convertPublicJwkToXml(signJwk, "signature") + "\n" +
      "-----END EC PUBLIC KEY FOR SIGNATURE-----";
  } else if (type === "private") {
    const encJwk = await crypto.subtle.exportKey("jwk", keyObj.enc.privateKey);
    const signJwk = await crypto.subtle.exportKey("jwk", keyObj.sign.privateKey);
    xml = 
      "-----BEGIN EC PRIVATE KEY FOR ENCRYPTION-----\n" +
      convertPrivateJwkToXml(encJwk, "encryption") + "\n" +
      "-----END EC PRIVATE KEY FOR ENCRYPTION-----\n" +
      "-----BEGIN EC PRIVATE KEY FOR SIGNATURE-----\n" +
      convertPrivateJwkToXml(signJwk, "signature") + "\n" +
      "-----END EC PRIVATE KEY FOR SIGNATURE-----";
  }
  const exportArea = document.getElementById("exportArea");
  exportArea.innerHTML = `<h3>${name} の ${type === "public" ? "公開鍵" : "秘密鍵"} エクスポート結果</h3>`;
  const textarea = document.createElement("textarea");
  textarea.rows = 10;
  textarea.value = xml;
  exportArea.appendChild(textarea);
  const blob = new Blob([xml], { type: "application/xml" });
  const url = URL.createObjectURL(blob);
  const downloadLink = document.createElement("a");
  downloadLink.href = url;
  downloadLink.download = name + (type === "public" ? ".pubkey" : ".pvtkey");
  downloadLink.textContent = "Download " + (type === "public" ? "公開鍵" : "秘密鍵");
  exportArea.appendChild(document.createElement("br"));
  exportArea.appendChild(downloadLink);
}
async function deleteKey(name) {
  if (!confirm("鍵 " + name + " を削除してよろしいですか？")) return;
  const transaction = db.transaction("keys", "readwrite");
  const store = transaction.objectStore("keys");
  store.delete(name);
  delete logicalKeys[name];
  alert("鍵 " + name + " を削除しました");
  clearExportArea();
  refreshKeyList();
}
document.getElementById("generateKeyButton").addEventListener("click", async function() {
  const keyName = document.getElementById("keyNameInput").value.trim();
  const regex = /^[A-Za-z0-9_\-@\.]+$/;
  if (!regex.test(keyName)) {
    alert("鍵名が不正です。英数字、_, -, @, . のみ使用可能です。");
    return;
  }
  if (logicalKeys[keyName]) {
    alert("同名の鍵が既に存在します");
    return;
  }
  await generateLogicalKeyPair(keyName);
});

function resetDatabase() {
  if (!confirm("本当に全ての鍵一覧を削除しますか？ この操作は元に戻せません。")) return;
  if (db) { db.close(); }
  const req = indexedDB.deleteDatabase("PubliCryptDB2");
  req.onsuccess = function() {
    alert("鍵一覧が初期化されました。");
    for (let key in logicalKeys) { delete logicalKeys[key]; }
    clearExportArea();
    refreshKeyList();
    initDB();
    resetUI();
  };
  req.onerror = function(e) { alert("鍵一覧の初期化中にエラーが発生しました。"); };
  req.onblocked = function(e) { alert("他のタブで開いている可能性があります。"); };
}
document.getElementById('resetDBBtn').addEventListener('click', resetDatabase);

// --- 公開鍵URL共有 ---
async function exportPubkeyUrl(name) {
  const keyObj = logicalKeys[name];
  if (!keyObj) { alert("鍵が見つかりません"); return; }
  // 暗号化(ECDH)公開鍵のみ配布
  const encJwk = await crypto.subtle.exportKey("jwk", keyObj.enc.publicKey);
  const xml = convertPublicJwkToXml(encJwk, "encryption");
  const utf8 = new TextEncoder().encode(xml);
  const b64 = btoa(String.fromCharCode(...utf8));
  const b64url = base64ToBase64Url(b64);
  const url = `https://calamaclir.github.io/index.html#pubkey=${b64url}`;
  const exportArea = document.getElementById("exportArea");
  exportArea.innerHTML = `<h3>${name} の 公開鍵URL</h3>
    <input type="text" value="${url}" readonly style="width:98%"><br>
    <button onclick="navigator.clipboard.writeText('${url}');this.textContent='コピーしました';">URLをコピー</button>
    <p>このURLを相手に共有することで、ワンクリックで公開鍵を受け渡せます。</p>`;
}

// --- 署名付き公開鍵URL共有 ---
async function signDataWithPrivateKey(signKeyObj, data) {
  const encoder = new TextEncoder();
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-512" } },
    signKeyObj.privateKey,
    encoder.encode(data)
  );
  return arrayBufferToBase64(signature);
}
async function exportPubkeyUrlWithSign(name) {
  const keyObj = logicalKeys[name];
  if (!keyObj) { alert("鍵が見つかりません"); return; }
  const encJwk = await crypto.subtle.exportKey("jwk", keyObj.enc.publicKey);
  const xml = convertPublicJwkToXml(encJwk, "encryption");
  const utf8 = new TextEncoder().encode(xml);
  const b64 = btoa(String.fromCharCode(...utf8));
  const b64url = base64ToBase64Url(b64);
  let sigBase64 = null;
  try {
    sigBase64 = await signDataWithPrivateKey(keyObj.sign, xml);
  } catch (e) {
    alert("署名に失敗: " + e);
    return;
  }
  const sigUrl = base64ToBase64Url(sigBase64);
  const url = `https://calamaclir.github.io/popup.html#pubkey=${b64url}&sig=${sigUrl}&signame=${encodeURIComponent(name)}`;
  const exportArea = document.getElementById("exportArea");
  exportArea.innerHTML = `<h3>${name} の 署名付き公開鍵URL</h3>
    <input type="text" value="${url}" readonly style="width:98%"><br>
    <button onclick="navigator.clipboard.writeText('${url}');this.textContent='コピーしました';">URLをコピー</button>
    <p>このURLを相手に共有することで、署名検証可能な公開鍵を送信できます。</p>`;
}

// --- 公開鍵インポート時の署名検証 ---
async function verifySignatureWithPublicKey(pubKey, data, sigBase64) {
  const encoder = new TextEncoder();
  const sigUint8 = base64ToUint8Array(sigBase64);
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-512" } },
    pubKey,
    sigUint8,
    encoder.encode(data)
  );
}
async function tryLoadPubkeyFromHash() {
  if (location.hash.startsWith("#pubkey=")) {
    try {
      const hashParams = {};
      location.hash.slice(1).split("&").forEach(part => {
        const [k, v] = part.split("=", 2);
        hashParams[k] = v;
      });
      const b64url = hashParams["pubkey"];
      const b64 = base64UrlToBase64(b64url);
      const bin = atob(b64);
      const uint8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; ++i) uint8[i] = bin.charCodeAt(i);
      const xml = new TextDecoder().decode(uint8);
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(xml, "application/xml");
      const x = xmlDoc.getElementsByTagName("X")[0].textContent.trim();
      const y = xmlDoc.getElementsByTagName("Y")[0].textContent.trim();
      const curve = xmlDoc.getElementsByTagName("Curve")[0]?.textContent.trim() || EC_CURVE;
      const jwk = { kty: "EC", crv: curve, x: x, y: y, ext: true };
      const cryptoKey = await crypto.subtle.importKey(
        "jwk", jwk,
        { name: "ECDH", namedCurve: curve },
        true, []
      );
      const identifier = arrayBufferToBase64(await crypto.subtle.exportKey("raw", cryptoKey));
      encryptionPublicKeys.push({ name: "URL受信公開鍵", identifier: identifier, cryptoKey: cryptoKey, type: "EC", curve: curve });

      const li = document.createElement('li');
      li.textContent = "URL受信公開鍵 (EC)";
      document.getElementById('pubKeyList').appendChild(li);

      let signInfoHtml = "";
      if (hashParams["sig"] && hashParams["signame"]) {
        const signame = decodeURIComponent(hashParams["signame"]);
        const sigBase64 = base64UrlToBase64(hashParams["sig"]);
        let verified = false;
        if (logicalKeys[signame] && logicalKeys[signame].sign && logicalKeys[signame].sign.publicKey) {
          try {
            const pubKey = logicalKeys[signame].sign.publicKey;
            verified = await verifySignatureWithPublicKey(pubKey, xml, sigBase64);
          } catch (e) { verified = false; }
        }
        if (verified) {
          signInfoHtml = `<span style="color:green;">署名付き公開鍵: ${signame}（署名検証OK）</span>`;
        } else if (logicalKeys[signame]) {
          signInfoHtml = `<span style="color:orange;">署名付き公開鍵: ${signame}（署名検証失敗）</span>`;
        } else {
          signInfoHtml = `<span style="color:gray;">署名付き公開鍵: ${signame}（ローカル公開鍵がなく検証未実施）</span>`;
        }
      } else {
        signInfoHtml = `<span style="color:gray;">署名なし公開鍵</span>`;
      }
      document.getElementById("pubkey-sign-info").innerHTML = signInfoHtml;

      alert("URLから公開鍵を受信しました");
      const pubkeyFileSelectBlock = document.getElementById('pubkey-file-select-block');
      if (pubkeyFileSelectBlock) pubkeyFileSelectBlock.style.display = "none";
    } catch (e) {
      alert("URL公開鍵の読み込みに失敗しました: " + e);
    }
  }
}

// --- ファイル暗号化/復号/ファイル選択 ---
const fileDropArea = document.getElementById('fileDropArea');
const fileListElem = document.getElementById('fileList');
fileDropArea.addEventListener('dragover', (e) => {
  e.preventDefault();
  fileDropArea.style.borderColor = "#000";
});
fileDropArea.addEventListener('dragleave', (e) => {
  e.preventDefault();
  fileDropArea.style.borderColor = "#888";
});
fileDropArea.addEventListener('drop', (e) => {
  e.preventDefault();
  fileDropArea.style.borderColor = "#888";
  const files = e.dataTransfer.files;
  for (let file of files) {
    filesToProcess.push(file);
    const li = document.createElement('li');
    li.textContent = file.name;
    fileListElem.appendChild(li);
  }
});
document.getElementById('fileSelect').addEventListener('change', (e) => {
  const files = e.target.files;
  for (let file of files) {
    filesToProcess.push(file);
    const li = document.createElement('li');
    li.textContent = file.name;
    fileListElem.appendChild(li);
  }
});

const pubKeyListElem = document.getElementById('pubKeyList');
document.getElementById('pubKeyInput').addEventListener('change', async (e) => {
  const files = e.target.files;
  for (let file of files) {
    const text = await file.text();
    try {
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(text, "application/xml");
      const x = xmlDoc.getElementsByTagName("X")[0].textContent.trim();
      const y = xmlDoc.getElementsByTagName("Y")[0].textContent.trim();
      const curve = xmlDoc.getElementsByTagName("Curve")[0]?.textContent.trim() || EC_CURVE;
      const jwk = { kty: "EC", crv: curve, x: x, y: y, ext: true };
      const cryptoKey = await crypto.subtle.importKey(
        "jwk", jwk,
        { name: "ECDH", namedCurve: curve },
        true, []
      );
      const raw = await crypto.subtle.exportKey("raw", cryptoKey);
      const identifier = arrayBufferToBase64(raw);
      encryptionPublicKeys.push({ name: file.name, identifier: identifier, cryptoKey: cryptoKey, type: "EC", curve: curve });
      const li = document.createElement('li');
      li.textContent = file.name + " (EC)";
      pubKeyListElem.appendChild(li);
    } catch(err) {
      alert("公開鍵 " + file.name + " のインポートエラー: " + err.message);
    }
  }
  e.target.value = "";
});

document.getElementById('encryptBtn').addEventListener('click', async () => {
  if (filesToProcess.length === 0) {
    alert("暗号化するファイルがありません。");
    return;
  }
  showSpinner();
  for (let file of filesToProcess) {
    await encryptFile(file);
  }
  resetUI();
});

async function encryptFile(file) {
  const aesKey = await crypto.subtle.generateKey(
    { name: AES_ALGORITHM, length: AES_KEY_LENGTH },
    true, ["encrypt", "decrypt"]
  );
  const aesKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
  const iv = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

  if (encryptionPublicKeys.length === 0) {
    alert("暗号化のために公開鍵がインポートされていません。");
    return;
  }
  const uniquePublicKeys = [];
  const seen = new Set();
  for (let pub of encryptionPublicKeys) {
    if (seen.has(pub.identifier)) continue;
    seen.add(pub.identifier);
    uniquePublicKeys.push(pub);
  }
  const entries = [];
  const encoder = new TextEncoder();
  for (let pub of uniquePublicKeys) {
    if (pub.type === "EC") {
      try {
        const ephemeralKeyPair = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: pub.curve },
          true, ["deriveKey"]
        );
        const wrappingKey = await crypto.subtle.deriveKey(
          { name: "ECDH", public: pub.cryptoKey },
          ephemeralKeyPair.privateKey,
          { name: AES_ALGORITHM, length: 256 },
          false, ["encrypt", "decrypt"]
        );
        const ephemeralPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralKeyPair.publicKey));
        const wrappingIV = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
        const wrappingCiphertextBuffer = await crypto.subtle.encrypt(
          { name: AES_ALGORITHM, iv: wrappingIV },
          wrappingKey,
          aesKeyRaw
        );
        const wrappingCiphertext = new Uint8Array(wrappingCiphertextBuffer);
        const wrappingOutput = concatUint8Arrays([wrappingIV, wrappingCiphertext]);
        const recipientIdBytes = base64ToUint8Array(pub.identifier);
        entries.push({
          type: 1,
          recipientId: recipientIdBytes,
          ephemeralPub: ephemeralPubRaw,
          wrappingOutput: wrappingOutput
        });
      } catch (err) {
        console.error("EC暗号化失敗: ", err);
      }
    }
  }
  if (entries.length === 0) {
    alert("有効な公開鍵がありません。");
    return;
  }
  const fileBuffer = new Uint8Array(await file.arrayBuffer());
  const fileNameBytes = encoder.encode(file.name);
  const payloadPlain = concatUint8Arrays([writeInt32LE(fileNameBytes.length), fileNameBytes, fileBuffer]);
  const payloadEnc = new Uint8Array(await crypto.subtle.encrypt(
    { name: AES_ALGORITHM, iv: iv },
    aesKey,
    payloadPlain
  ));
  let parts = [];
  parts.push(writeInt32LE(entries.length));
  for (let entry of entries) {
    parts.push(new Uint8Array([entry.type]));
    if (entry.type === 1) {
      parts.push(writeInt32LE(entry.recipientId.length));
      parts.push(entry.recipientId);
      parts.push(writeInt32LE(entry.ephemeralPub.length));
      parts.push(entry.ephemeralPub);
      parts.push(writeInt32LE(entry.wrappingOutput.length));
      parts.push(entry.wrappingOutput);
    }
  }
  parts.push(iv);
  parts.push(payloadEnc);
  const finalData = concatUint8Arrays(parts);
  const blob = new Blob([finalData], { type: "application/octet-stream" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = file.name + ".crypted";
  a.click();
}

document.getElementById('decryptBtn').addEventListener('click', async () => {
  if (filesToProcess.length === 0) {
    alert("復号するファイルがありません。");
    return;
  }
  showSpinner();
  for (let file of filesToProcess) {
    await decryptFile(file);
  }
  resetUI();
});

async function decryptFile(file) {
  try {
    const fileBuffer = new Uint8Array(await file.arrayBuffer());
    const view = new DataView(fileBuffer.buffer);
    let offset = 0;
    if (fileBuffer.length < 4) {
      throw new Error("ファイルが不正です。");
    }
    const entryCount = readInt32LE(view, offset);
    offset += 4;
    const headerEntries = [];
    const decoder = new TextDecoder();
    for (let i = 0; i < entryCount; i++) {
      const type = fileBuffer[offset];
      offset += 1;
      if (type === 1) {
        const idLen = readInt32LE(view, offset);
        offset += 4;
        const recipientId = fileBuffer.slice(offset, offset + idLen);
        offset += idLen;
        const ephLen = readInt32LE(view, offset);
        offset += 4;
        const ephemeralPub = fileBuffer.slice(offset, offset + ephLen);
        offset += ephLen;
        const wrapLen = readInt32LE(view, offset);
        offset += 4;
        const wrappingOutput = fileBuffer.slice(offset, offset + wrapLen);
        offset += wrapLen;
        headerEntries.push({ type: 1, recipientId: recipientId, ephemeralPub: ephemeralPub, wrappingOutput: wrappingOutput });
      } else {
        throw new Error("不明な鍵エントリータイプです。");
      }
    }
    if (offset + AES_IV_LENGTH > fileBuffer.length) {
      throw new Error("ファイルが不正です。");
    }
    const iv = fileBuffer.slice(offset, offset + AES_IV_LENGTH);
    offset += AES_IV_LENGTH;
    const payloadEnc = fileBuffer.slice(offset);
    let aesKeyRaw;
    let found = false;

    // 復号用秘密鍵は「全logicalKeys」の「enc.privateKey」で試す
    for (let entry of headerEntries) {
      if (entry.type === 1) {
        const entryIdBase64 = arrayBufferToBase64(entry.recipientId);
        for (let keyName in logicalKeys) {
          const keyObj = logicalKeys[keyName];
          const pubRaw = await crypto.subtle.exportKey("raw", keyObj.enc.publicKey);
          const id = arrayBufferToBase64(pubRaw);
          if (id === entryIdBase64) {
            const ephemeralPubKey = await crypto.subtle.importKey(
              "raw", entry.ephemeralPub,
              { name: "ECDH", namedCurve: keyObj.enc.curve },
              true, []
            );
            const wrappingKey = await crypto.subtle.deriveKey(
              { name: "ECDH", public: ephemeralPubKey },
              keyObj.enc.privateKey,
              { name: AES_ALGORITHM, length: 256 },
              false, ["decrypt"]
            );
            const wrappingIV = entry.wrappingOutput.slice(0, AES_IV_LENGTH);
            const wrappingCiphertext = entry.wrappingOutput.slice(AES_IV_LENGTH);
            try {
              const decrypted = await crypto.subtle.decrypt(
                { name: AES_ALGORITHM, iv: wrappingIV },
                wrappingKey,
                wrappingCiphertext
              );
              aesKeyRaw = new Uint8Array(decrypted);
              found = true;
              break;
            } catch (err) { }
          }
        }
      }
      if (found) break;
    }
    if (!found || !aesKeyRaw) {
      throw new Error("一致する秘密鍵が見つからないか、AES鍵の復号に失敗しました。");
    }
    const aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: AES_ALGORITHM }, true, ["decrypt"]);
    let payloadPlainBuffer;
    try {
      payloadPlainBuffer = await crypto.subtle.decrypt({ name: AES_ALGORITHM, iv: iv }, aesKey, payloadEnc);
    } catch (err) {
      throw new Error("AES復号に失敗しました: " + err.message);
    }
    const payloadPlain = new Uint8Array(payloadPlainBuffer);
    const dv = new DataView(payloadPlain.buffer);
    if (payloadPlain.length < 4) {
      throw new Error("復号結果が不正です。");
    }
    const fnameLen = dv.getInt32(0, true);
    if (4 + fnameLen > payloadPlain.length) {
      throw new Error("復号結果が不正です。");
    }
    const fnameBytes = payloadPlain.slice(4, 4 + fnameLen);
    const originalFileName = new TextDecoder().decode(fnameBytes);
    const fileContent = payloadPlain.slice(4 + fnameLen);
    const blob = new Blob([fileContent], { type: "application/octet-stream" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = originalFileName;
    a.click();
  } catch (err) {
    alert("復号エラー: " + err.message);
  }
}

// --- ページロード時初期化 ---
window.addEventListener("load", async () => {
  await initDB();
  await tryLoadPubkeyFromHash();
});
