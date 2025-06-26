// ── 定数定義 ──
const EC_ALGORITHM = "ECDH";
const DEFAULT_EC_CURVE = "P-521";
const AES_ALGORITHM = "AES-GCM";
const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12;

// ── グローバル変数 ──
let db;
const keyStore = {};
const importedPrivateKeys = [];
const encryptionPublicKeys = [];
const filesToProcess = [];
// UIブロックIDリスト（必要に応じて増減可）
const HIDEABLE_UI_BLOCK_IDS = [
  'pubkey-file-select-block',
  'decrypt-block',
  'privKeyImport',
  'keyManagement',
  'exportArea',
  'resetSection',
  'decrypt-block'
];

// ── UI補助関数 ──
function showSpinner() {
  document.getElementById('spinner').style.display = 'block';
}
function hideSpinner() {
  document.getElementById('spinner').style.display = 'none';
}
function clearExportArea() {
  document.getElementById("exportArea").innerHTML = "";
}
// --- UI初期化時 ---
function resetUI() {
  filesToProcess.length = 0;
  encryptionPublicKeys.length = 0;
  document.getElementById('fileList').innerHTML = "";
  document.getElementById('fileDropArea').textContent = "ここにファイルをドロップ";
  document.getElementById('pubKeyList').innerHTML = "";
  document.getElementById('fileSelect').value = "";
  document.getElementById('privKeyList').innerHTML = "";
  hideSpinner();

  // --- 非表示を「表示」に戻す ---
  setBlocksDisplay(HIDEABLE_UI_BLOCK_IDS, "");
}

// --- UI初期化時 ---
function resetUIEncrypt() {
  filesToProcess.length = 0;
  document.getElementById('fileList').innerHTML = "";
  document.getElementById('fileDropArea').textContent = "ここにファイルをドロップ";
  document.getElementById('fileSelect').value = "";
  hideSpinner();

}

// ── ユーティリティ関数 ──
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

// ── IndexedDB 関連 ──
function initDB() {
  const request = indexedDB.open("PubliCryptDB", 2);
  request.onupgradeneeded = function(e) {
    db = e.target.result;
    if (!db.objectStoreNames.contains("keys")) {
      db.createObjectStore("keys", { keyPath: "name" });
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
function storeKeyRecord(record) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e);
  });
}
function deleteKeyRecord(name) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const req = store.delete(name);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e);
  });
}
function getKeyRecord(name) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readonly");
    const store = transaction.objectStore("keys");
    const req = store.get(name);
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e);
  });
}
async function storeKeyPair(name, type, publicJwk, privateJwk) {
  let record = await getKeyRecord(name);
  if (!record) {
    record = { name: name, type: type, publicKeyJwk: publicJwk, privateKeyJwk: privateJwk };
  } else {
    record.type = type;
    record.publicKeyJwk = publicJwk;
    record.privateKeyJwk = privateJwk;
  }
  await storeKeyRecord(record);
}
async function loadKeysFromDB() {
  const transaction = db.transaction("keys", "readonly");
  const store = transaction.objectStore("keys");
  const req = store.getAll();
  req.onsuccess = async function() {
    const records = req.result;
    for (const record of records) {
      if (record.publicKeyJwk && record.type === "EC") {
        const pubKey = await crypto.subtle.importKey(
          "jwk", record.publicKeyJwk,
          { name: EC_ALGORITHM, namedCurve: record.publicKeyJwk.crv },
          true, []
        );
        if (!keyStore[record.name]) { keyStore[record.name] = {}; }
        keyStore[record.name].publicKey = pubKey;
        keyStore[record.name].type = "EC";
        keyStore[record.name].curve = record.publicKeyJwk.crv;
      }
      if (record.privateKeyJwk && record.type === "EC") {
        const privKey = await crypto.subtle.importKey(
          "jwk", record.privateKeyJwk,
          { name: EC_ALGORITHM, namedCurve: record.publicKeyJwk.crv },
          true, ["deriveKey"]
        );
        const raw = await crypto.subtle.exportKey("raw", keyStore[record.name].publicKey);
        const identifier = arrayBufferToBase64(raw);
        importedPrivateKeys.push({ name: record.name, identifier: identifier, cryptoKey: privKey, type: "EC" });
        if (!keyStore[record.name]) { keyStore[record.name] = {}; }
        keyStore[record.name].privateKey = privKey;
      }
    }
    refreshKeyList();
  }
}

// ── XML形式の鍵インポート（統合版） ──
function getXmlTagContent(xmlDoc, tagName) {
  const el = xmlDoc.getElementsByTagName(tagName)[0];
  return el ? el.textContent.trim() : null;
}
async function importPublicKeyFromXmlEC(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const x = getXmlTagContent(xmlDoc, "X");
  const y = getXmlTagContent(xmlDoc, "Y");
  const curve = getXmlTagContent(xmlDoc, "Curve") || DEFAULT_EC_CURVE;
  if (!x || !y) {
    throw new Error("公開鍵XMLに X または Y が見つかりません");
  }
  const jwk = { kty: "EC", crv: curve, x: x, y: y, ext: true };
  const cryptoKey = await crypto.subtle.importKey(
    "jwk", jwk,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, []
  );
  const raw = await crypto.subtle.exportKey("raw", cryptoKey);
  const identifier = arrayBufferToBase64(raw);
  return { name: fileName, identifier: identifier, cryptoKey: cryptoKey, type: "EC", curve: curve };
}
async function importPrivateKeyFromXmlEC(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const x = getXmlTagContent(xmlDoc, "X");
  const y = getXmlTagContent(xmlDoc, "Y");
  const d = getXmlTagContent(xmlDoc, "D");
  const curve = getXmlTagContent(xmlDoc, "Curve") || DEFAULT_EC_CURVE;
  if (!x || !y || !d) {
    throw new Error("秘密鍵XMLに必要な要素が見つかりません");
  }
  const jwkPrivate = { kty: "EC", crv: curve, x: x, y: y, d: d, ext: true };
  const privateCryptoKey = await crypto.subtle.importKey(
    "jwk", jwkPrivate,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, ["deriveKey"]
  );
  const publicJwk = { kty: "EC", crv: curve, x: x, y: y, ext: true };
  const publicCryptoKey = await crypto.subtle.importKey(
    "jwk", publicJwk,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, []
  );
  const raw = await crypto.subtle.exportKey("raw", publicCryptoKey);
  const identifier = arrayBufferToBase64(raw);
  return { name: fileName, identifier: identifier, publicKey: publicCryptoKey, privateKey: privateCryptoKey, type: "EC", curve: curve };
}
async function importPublicKeyFromXmlUnified(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const rootTag = xmlDoc.documentElement.tagName;
  if (rootTag === "ECKeyValue") {
    return await importPublicKeyFromXmlEC(xmlString, fileName);
  } else {
    throw new Error("公開鍵XMLの形式が不明です");
  }
}
async function importPrivateKeyFromXmlUnified(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const rootTag = xmlDoc.documentElement.tagName;
  if (rootTag === "ECKeyValue") {
    return await importPrivateKeyFromXmlEC(xmlString, fileName);
  } else {
    throw new Error("秘密鍵XMLの形式が不明です");
  }
}

// ── ファイルドラッグ＆ドロップ／選択処理 ──
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

// ── 公開鍵ファイル入力（暗号化用）：読み込んだ鍵は encryptionPublicKeys に登録する ──
const pubKeyListElem = document.getElementById('pubKeyList');
document.getElementById('pubKeyInput').addEventListener('change', async (e) => {
  const files = e.target.files;
  for (let file of files) {
    const text = await file.text();
    try {
      const pubKey = await importPublicKeyFromXmlUnified(text, file.name);
      encryptionPublicKeys.push(pubKey);
      const li = document.createElement('li');
      li.textContent = pubKey.name + " (" + pubKey.type + ")";
      pubKeyListElem.appendChild(li);
    } catch(err) {
      alert("公開鍵 " + file.name + " のインポートエラー: " + err.message);
    }
  }
  e.target.value = "";
});

// ── 秘密鍵ファイル入力（インポート＆DB保存、公開鍵自動生成） ──
const privKeyListElem = document.getElementById('privKeyList');
document.getElementById('privKeyInput').addEventListener('change', async (e) => {
  let imported = false;
  const files = e.target.files;
  for (let file of files) {
    const text = await file.text();
    try {
      let keyName = file.name;
      if (keyName.toLowerCase().endsWith(".pvtkey")) {
        keyName = keyName.slice(0, -7);
      }
      if (keyStore[keyName]) {
        alert("秘密鍵 " + keyName + " は既に存在するため、インポートをスキップします。");
        continue;
      }
      const keyPair = await importPrivateKeyFromXmlUnified(text, keyName);
      keyStore[keyPair.name] = { 
        publicKey: keyPair.publicKey, 
        privateKey: keyPair.privateKey, 
        type: keyPair.type,
        curve: keyPair.curve
      };
      importedPrivateKeys.push({ name: keyPair.name, identifier: keyPair.identifier, cryptoKey: keyPair.privateKey, type: keyPair.type });
      const li = document.createElement('li');
      li.textContent = keyPair.name + " (" + keyPair.type + ")";
      privKeyListElem.appendChild(li);
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      await storeKeyPair(keyPair.name, keyPair.type, publicJwk, privateJwk);
      refreshKeyList();
      clearExportArea();
      imported = true;
    } catch(err) {
      alert("秘密鍵 " + file.name + " のインポートエラー: " + err.message);
    }
  }
  e.target.value = "";
  if(imported){
    alert("秘密鍵インポート完了");
  }
  resetUI();
});

// ── ファイル暗号化処理（統合版） ──
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
    if (seen.has(pub.identifier)) {
      continue;
    }
    seen.add(pub.identifier);
    uniquePublicKeys.push(pub);
  }
  const entries = [];
  const encoder = new TextEncoder();
  for (let pub of uniquePublicKeys) {
    if (pub.type === "EC") {
      try {
        const ephemeralKeyPair = await crypto.subtle.generateKey(
          { name: EC_ALGORITHM, namedCurve: pub.curve },
          true, ["deriveKey"]
        );
        const wrappingKey = await crypto.subtle.deriveKey(
          { name: EC_ALGORITHM, public: pub.cryptoKey },
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

// ── ファイル復号処理（統合版） ──
async function decryptFile(file) {
  try {
    if (importedPrivateKeys.length === 0) {
      throw new Error("復号のための秘密鍵が存在しません。");
    }
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
    for (let entry of headerEntries) {
      if (entry.type === 1) {
        const entryIdBase64 = arrayBufferToBase64(entry.recipientId);
        for (let priv of importedPrivateKeys.filter(k => k.type === "EC")) {
          if (priv.identifier === entryIdBase64) {
            const ephemeralPubKey = await crypto.subtle.importKey(
              "raw", entry.ephemeralPub,
              { name: EC_ALGORITHM, namedCurve: keyStore[priv.name].curve },
              true, []
            );
            const wrappingKey = await crypto.subtle.deriveKey(
              { name: EC_ALGORITHM, public: ephemeralPubKey },
              priv.cryptoKey,
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
    const originalFileName = decoder.decode(fnameBytes);
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

// ── ボタン押下処理 ──
document.getElementById('encryptBtn').addEventListener('click', async () => {
  if (filesToProcess.length === 0) {
    alert("暗号化するファイルがありません。");
    return;
  }
  showSpinner();
  for (let file of filesToProcess) {
    await encryptFile(file);
  }
  resetUIEncrypt();
  hideSpinner();
});
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

// ── 鍵生成（統合版）：選択されたアルゴリズムに応じて鍵ペア生成 ──
async function generateKeyPair(name, algType) {
  if (algType === "EC") {
    try {
      const keyPair = await crypto.subtle.generateKey(
        { name: EC_ALGORITHM, namedCurve: DEFAULT_EC_CURVE },
        true, ["deriveKey", "deriveBits"]
      );
      keyStore[name] = { 
        publicKey: keyPair.publicKey, 
        privateKey: keyPair.privateKey, 
        type: "EC",
        curve: DEFAULT_EC_CURVE
      };
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      await storeKeyPair(name, "EC", publicJwk, privateJwk);
      const raw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
      const identifier = arrayBufferToBase64(raw);
      importedPrivateKeys.push({ name: name, identifier: identifier, cryptoKey: keyPair.privateKey, type: "EC" });
      alert("楕円曲線鍵ペア生成完了: " + name);
      refreshKeyList();
    } catch (e) {
      console.error(e);
      alert("楕円曲線鍵生成エラー: " + e);
    }
  } else {
    alert("選択されたアルゴリズムはサポートされていません。");
  }
}

// ── 公開鍵URL共有機能（追加分） ──
async function exportPubkeyUrl(name) {
  const keyPair = keyStore[name];
  if (!keyPair || !keyPair.publicKey) {
    alert("公開鍵が見つかりません");
    return;
  }
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const xml = convertPublicJwkToXml(jwk);
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

// ── 鍵一覧の再表示：公開鍵URL共有ボタンを追加 ──
function refreshKeyList() {
  const tbody = document.getElementById("keyTable").querySelector("tbody");
  tbody.innerHTML = "";
  for (const name in keyStore) {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.textContent = name;
    tr.appendChild(tdName);

    const tdType = document.createElement("td");
    tdType.textContent = keyStore[name].type;
    tr.appendChild(tdType);

    const tdKeyInfo = document.createElement("td");
    if (keyStore[name].type === "EC") {
      tdKeyInfo.textContent = keyStore[name].curve ? keyStore[name].curve : "N/A";
    } else {
      tdKeyInfo.textContent = "N/A";
    }
    tr.appendChild(tdKeyInfo);

    const tdOps = document.createElement("td");

    const exportPubBtn = document.createElement("button");
    exportPubBtn.textContent = "公開鍵エクスポート";
    exportPubBtn.onclick = () => exportKey(name, "public");

    const exportPubUrlBtn = document.createElement("button");
    exportPubUrlBtn.textContent = "公開鍵URL共有";
    exportPubUrlBtn.onclick = () => exportPubkeyUrl(name);

    const exportPrivBtn = document.createElement("button");
    exportPrivBtn.textContent = "秘密鍵エクスポート";
    exportPrivBtn.classList.add('export-privkey-btn');
    exportPrivBtn.onclick = () => {
      if (confirm("【注意】秘密鍵のエクスポートは非常に危険です。秘密鍵が漏洩すると、暗号化されたデータが復号不能になったり、システム全体の安全性が損なわれる可能性があります。\n\n本当に秘密鍵をエクスポートしてもよろしいですか？")) {
        exportKey(name, "private");
      }
    };

    const deleteBtn = document.createElement("button");
    deleteBtn.textContent = "削除";
    deleteBtn.onclick = () => deleteKey(name);

    tdOps.appendChild(exportPubBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(exportPubUrlBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(exportPrivBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(deleteBtn);
    tr.appendChild(tdOps);

    tbody.appendChild(tr);
  }
}

// ── 鍵エクスポート（統合版）：鍵種に応じてXML形式に変換 ──
function convertPublicJwkToXml(jwk) {
  if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y></ECKeyValue>`;
  }
}
function convertPrivateJwkToXml(jwk) {
  if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y><D>${jwk.d}</D></ECKeyValue>`;
  }
}
async function exportKey(name, type) {
  const keyPair = keyStore[name];
  let key;
  if (type === "public") {
    if (!keyPair.publicKey) { alert("公開鍵が存在しません"); return; }
    key = keyPair.publicKey;
  } else if (type === "private") {
    if (!keyPair.privateKey) { alert("秘密鍵が存在しません"); return; }
    key = keyPair.privateKey;
  }
  try {
    const jwk = await crypto.subtle.exportKey("jwk", key);
    let xml;
    if (type === "public") {
      xml = convertPublicJwkToXml(jwk);
    } else {
      xml = convertPrivateJwkToXml(jwk);
    }
    const exportArea = document.getElementById("exportArea");
    if (type === "private") {
      exportArea.innerHTML = `<h3>${name} の 秘密鍵 エクスポート</h3>
                              <p style="color: red; font-weight: bold;">※ 秘密鍵は非常にセンシティブな情報です。取り扱いには十分ご注意ください。</p>`;
    } else {
      exportArea.innerHTML = `<h3>${name} の 公開鍵 エクスポート</h3>`;
    }
    const textarea = document.createElement("textarea");
    textarea.rows = 10;
    textarea.value = xml;
    exportArea.appendChild(textarea);

    const blob = new Blob([xml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);

    // --- ボタン化したダウンロードリンク ---
    const downloadBtn = document.createElement("button");
    downloadBtn.textContent = "ダウンロード" + (type === "public" ? "公開鍵" : "秘密鍵");
    downloadBtn.style.marginTop = "8px";
    // 色付け：公開鍵=青, 秘密鍵=赤
    if (type === "private") {
      downloadBtn.style.backgroundColor = "#e53935";
      downloadBtn.style.color = "#fff";
      downloadBtn.style.border = "none";
    } else {
      downloadBtn.style.backgroundColor = "#2979ff";
      downloadBtn.style.color = "#fff";
      downloadBtn.style.border = "none";
    }
    downloadBtn.style.padding = "8px 16px";
    downloadBtn.style.borderRadius = "6px";
    downloadBtn.style.fontWeight = "bold";
    downloadBtn.onclick = function() {
      const a = document.createElement("a");
      a.href = url;
      a.download = name + (type === "public" ? ".pubkey" : ".pvtkey");
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    };

    exportArea.appendChild(document.createElement("br"));
    exportArea.appendChild(downloadBtn);
  } catch (e) {
    console.error(e);
    alert("エクスポートエラー: " + e);
  }
}

async function deleteKey(name) {
  if (!confirm("鍵 " + name + " を削除してよろしいですか？")) return;
  try {
    await deleteKeyRecord(name);
  } catch (e) {
    console.error("DB削除エラー", e);
  }
  delete keyStore[name];
  let privIndex = importedPrivateKeys.findIndex(k => k.name === name);
  if (privIndex >= 0) { importedPrivateKeys.splice(privIndex, 1); }
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
  if (keyStore[keyName]) {
    alert("同名の鍵が既に存在します");
    return;
  }
  const algSelect = document.getElementById("keyAlgorithmSelect");
  const algType = algSelect.value;
  await generateKeyPair(keyName, algType);
});

// ── IndexedDB初期化（リセット） ──
function resetDatabase() {
  if (!confirm("本当に全ての鍵一覧を削除しますか？ この操作は元に戻せません。")) return;
  if (db) { db.close(); }
  const req = indexedDB.deleteDatabase("PubliCryptDB");
  req.onsuccess = function() {
    alert("鍵一覧が初期化されました。");
    for (let key in keyStore) { delete keyStore[key]; }
    importedPrivateKeys.length = 0;
    clearExportArea();
    db = null;
    refreshKeyList();
    initDB();
  };
  req.onerror = function(e) {
    alert("鍵一覧の初期化中にエラーが発生しました。");
  };
  req.onblocked = function(e) {
    alert("他のタブで開いている可能性があります。");
  };
}
document.getElementById('resetDBBtn').addEventListener('click', resetDatabase);

// ── ページ起動時: #pubkey= で公開鍵を読み込む（追加分） ──
// 複数ブロックの表示/非表示切り替え用
function setBlocksDisplay(ids, displayStyle) {
  ids.forEach(id => {
    // idかクラス名か判定（id優先）
    let el = document.getElementById(id);
    if (el) {
      el.style.display = displayStyle;
    } else {
      // idがなければclassとして取得し全部切り替え
      let classElems = document.getElementsByClassName(id);
      for (let i = 0; i < classElems.length; i++) {
        classElems[i].style.display = displayStyle;
      }
    }
  });
}

// --- ページ起動時: #pubkey= で公開鍵を読み込む＆UI非表示処理 ---
async function tryLoadPubkeyFromHash() {
  if (location.hash.startsWith("#pubkey=")) {
    try {
      const b64url = location.hash.slice(8);
      const b64 = base64UrlToBase64(b64url);
      const bin = atob(b64);
      const uint8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; ++i) uint8[i] = bin.charCodeAt(i);
      const xml = new TextDecoder().decode(uint8);
      const pubKey = await importPublicKeyFromXmlUnified(xml, "URL受信公開鍵");
      encryptionPublicKeys.push(pubKey);
      const li = document.createElement('li');
      li.textContent = pubKey.name + " (" + pubKey.type + ")";
      document.getElementById('pubKeyList').appendChild(li);
      alert("URLから公開鍵を受信しました");

      // --- まとめてUI非表示 ---
      setBlocksDisplay(HIDEABLE_UI_BLOCK_IDS, "none");

    } catch (e) {
      alert("URL公開鍵の読み込みに失敗しました: " + e);
    }
  }
}

// --- ページロード時にDB初期化・URL公開鍵読込
window.addEventListener("load", async () => {
  await initDB();
  await tryLoadPubkeyFromHash();
});

// 末尾やwindow.load直後などでOK
document.getElementById('resetUiBtn').addEventListener('click', resetUI);
