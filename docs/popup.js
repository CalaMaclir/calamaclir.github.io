// ── 定数定義 ──
const EC_ALGORITHM = "ECDH";
const DEFAULT_EC_CURVE = "P-521";
const X25519_ALGORITHM = "X25519"; // 追加: X25519用

const AES_ALGORITHM = "AES-GCM";
const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12;
const PUBKEY_SHARE_BASE_URL = "https://calamaclir.github.io/index.html";
const HEADER_CHECK_SIZE = 1024 * 1024;
const MAGIC_REQ_PARAM = "magic_req";
const MAGIC_SENDER_PARAM = "sender";
const DECRYPT_MODE_HASH = "decrypt_mode";

// ── 暗号ファイル v2（後方互換: 旧ファイルも復号可能） ──
// 旧フォーマット: [entryCount][entries...][iv12][payloadEnc]
// 新フォーマット: [entryCount][entries...][MAGIC4][fileNonce16][iv12][payloadEnc]
// - MAGIC4 は v2 判定用（旧実装は読めないが、新実装は旧/新どちらも復号できる）
// - fileNonce16 は HKDF の salt 兼、誤復号・誤解釈の事故低減に使う
const FILE_V2_MAGIC = new Uint8Array([0x50, 0x43, 0x32, 0x00]); // "PC2\0"
const FILE_NONCE_LENGTH = 16;

// ファイルヘッダーのエントリータイプ
const ENTRY_TYPE_P521 = 1;
const ENTRY_TYPE_X25519 = 2; // 追加: X25519用の識別子

// v2 追加ブロック
const FILE_V2_MARKER = new Uint8Array([0x50, 0x43, 0x32, 0x00]); // "PC2\0"


// HKDF info 固定プレフィックス（将来互換のため文字列を固定）
const HKDF_INFO_WRAP_PREFIX = "PubliCrypt|wrap|v2|";
const HKDF_INFO_PAYLOAD_PREFIX = "PubliCrypt|payload|v2";

// ── i18n リソース (UI表示用) ──
// ★ resources オブジェクトは i18n.js に移動したため削除 ★
// ── グローバル変数 ──
let db;
const keyStore = {};
const importedPrivateKeys = [];
const encryptionPublicKeys = [];
const filesToProcess = [];
let currentLang = 'ja'; // デフォルト

const HIDEABLE_UI_BLOCK_IDS = [
  'pubkey-file-select-block',
  'decrypt-block',
  'privKeyImport',
  'keyManagement',
  'exportArea',
  'resetSection',
  'magicLinkSection'
];

// ── i18n ヘルパー ──
function t(key, params = {}) {
  let text = resources[currentLang][key] || resources['en'][key] || key;
  for (const [k, v] of Object.entries(params)) {
    text = text.replace(`{${k}}`, v);
  }
  return text;
}

function updateUIText() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    el.innerHTML = t(key);
  });
  const keyNameInput = document.getElementById('keyNameInput');
  if(keyNameInput) keyNameInput.placeholder = t('key_name_placeholder');

  // 言語スイッチャー
  ['ja', 'en', 'fr', 'lb'].forEach(lang => {
      const el = document.getElementById(`lang-${lang}`);
      if(el) el.className = currentLang === lang ? 'active' : '';
  });
  
  refreshKeyList(); 
}

function changeLanguage(lang) {
  currentLang = lang;
  updateUIText();
}

// ── Fingerprint生成関数 ──
async function calcFingerprint(publicKey) {
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  const hash = await crypto.subtle.digest("SHA-256", raw);
  let b64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return b64;
}

// 既存のFPから4桁の数字を派生させる
async function calcConfirmationKey(fingerprint) {
  if (!fingerprint) return "----";
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(fingerprint));
  const hashArray = new Uint8Array(hashBuffer);
  // 先頭4バイトから数値を生成
  const view = new DataView(hashArray.buffer);
  const val = view.getUint32(0); 
  return (val % 10000).toString().padStart(4, '0');
}

// ── UI補助関数 ──
function showSpinner(text) {
  const spinner = document.getElementById('spinner');
  spinner.textContent = text || t('processing');
  spinner.style.display = 'block';
}
function updateSpinnerText(text) {
    document.getElementById('spinner').textContent = text;
}
function hideSpinner() {
  document.getElementById('spinner').style.display = 'none';
}
function clearExportArea() {
  const exportArea = document.getElementById('exportArea');
  exportArea.textContent = "";
  exportArea.style.display = 'none';
}
function dispExportArea() {
  document.getElementById('exportArea').style.display = '';
}

function hideResetUiButtonsInExtension() {
  if (typeof chrome !== "undefined" && typeof chrome.runtime !== "undefined") {
    const UIinitArea = document.getElementById('UI-init');
    if (UIinitArea) UIinitArea.style.display = "none";
  }
}

// --- UI初期化時 ---
function resetUI() {
  filesToProcess.length = 0;
  encryptionPublicKeys.length = 0;
  document.getElementById('fileList').textContent = "";
  document.getElementById('fileDropArea').innerHTML = t('drop_area_text');
  document.getElementById('pubKeyList').textContent = "";
  document.getElementById('fileSelect').value = "";
  document.getElementById('privKeyList').textContent = "";
  hideSpinner();
  clearExportArea();
  
  history.replaceState(null, null, ' ');

  const wizard = document.getElementById('magicLinkWizard');
  if (wizard) wizard.style.display = 'none';
  
  const mainApp = document.getElementById('main-app-container');
  if (mainApp) mainApp.style.display = 'block';

  setBlocksDisplay(HIDEABLE_UI_BLOCK_IDS, "");

  const reloadBtn = document.getElementById('reloadURLBtn');
  if (reloadBtn) reloadBtn.style.display = '';

  document.querySelector('h1').innerText = "PubliCrypt";
  const fileSecHeader = document.querySelector('#fileSection h2');
  if(fileSecHeader) fileSecHeader.innerHTML = t('target_files_header');

  const encryptSection = document.getElementById('encryptSection');
  if (encryptSection) encryptSection.style.display = '';
  
  const encryptBtn = document.getElementById('encryptBtn');
  if (encryptBtn) encryptBtn.style.display = '';

  const decryptBtn = document.getElementById('decryptBtn');
  if (decryptBtn) {
      decryptBtn.style.width = "";
      decryptBtn.style.fontSize = "";
      decryptBtn.style.marginTop = "";
  }
  const decryptBlock = document.querySelector('.decrypt-block');
  if (decryptBlock) {
      decryptBlock.style.display = "";
      decryptBlock.style.width = "";
  }
}

function resetUIEncrypt() {
  filesToProcess.length = 0;
  document.getElementById('fileList').textContent = "";
  document.getElementById('fileDropArea').textContent = t('drop_area_text');
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

// ── クリプト補助（v2） ──
async function sha256Bytes(u8) {
  const buf = await crypto.subtle.digest("SHA-256", (u8 instanceof Uint8Array) ? u8 : new Uint8Array(u8));
  return new Uint8Array(buf);
}

// JWK import 時の互換化（key_ops衝突回避）
function normalizeJwkForImport(jwk) {
  // structuredClone があればそれを優先でもOK
  const copy = (typeof structuredClone === "function")
    ? structuredClone(jwk)
    : JSON.parse(JSON.stringify(jwk));
  // WebCrypto の importKey(usages) と衝突しやすいので落とす
  delete copy.key_ops;
  // ついでに衝突源になりやすいフィールドも落として安全側
  delete copy.use;
  delete copy.alg;
  return copy;
}


function eqBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function deriveAesGcmKeyFromSharedSecret(sharedSecretU8, saltU8, infoU8, usages) {
  // HKDF-Extract/Expand を WebCrypto で実施し、AES-256-GCM 鍵へ
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecretU8,
    "HKDF",
    false,
    ["deriveKey"]
  );
  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltU8,
      info: infoU8,
    },
    hkdfKey,
    { name: AES_ALGORITHM, length: AES_KEY_LENGTH },
    false,
    usages
  );
}

async function deriveSharedSecretBits(algType, privateKey, publicKey) {
  // ECDH/X25519 ともに 256bit を IKM として使う（HKDF で安全側へ寄せる）
  const bits = await crypto.subtle.deriveBits(
    { name: algType, public: publicKey },
    privateKey,
    256
  );
  return new Uint8Array(bits);
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

// DBから鍵を読み込み（アルゴリズム分岐対応）
async function loadKeysFromDB() {
  const transaction = db.transaction("keys", "readonly");
  const store = transaction.objectStore("keys");
  const req = store.getAll();
  req.onsuccess = async function() {
    const records = req.result;
    for (const record of records) {
      if (!keyStore[record.name]) { keyStore[record.name] = {}; }

      // 既存の EC (P-521) 読み込み
      if (record.publicKeyJwk && record.type === "EC") {
        const pubKey = await crypto.subtle.importKey(
          "jwk", normalizeJwkForImport(record.publicKeyJwk),
          { name: EC_ALGORITHM, namedCurve: record.publicKeyJwk.crv },
          true, []
        );
        keyStore[record.name].publicKey = pubKey;
        keyStore[record.name].type = "EC";
        keyStore[record.name].curve = record.publicKeyJwk.crv;
        keyStore[record.name].fingerprint = await calcFingerprint(pubKey);
      }
      if (record.privateKeyJwk && record.type === "EC") {
        const privKey = await crypto.subtle.importKey(
          "jwk", normalizeJwkForImport(record.privateKeyJwk),
          { name: EC_ALGORITHM, namedCurve: record.publicKeyJwk.crv },
          true, ["deriveKey", "deriveBits"]
        );
        const raw = await crypto.subtle.exportKey("raw", keyStore[record.name].publicKey);
        const identifier = arrayBufferToBase64(raw);
        importedPrivateKeys.push({ name: record.name, identifier: identifier, cryptoKey: privKey, type: "EC" });
        keyStore[record.name].privateKey = privKey;
      }

      // 【追加】 X25519 読み込み
      if (record.publicKeyJwk && record.type === X25519_ALGORITHM) {
        // X25519は namedCurve 不要、 name: "X25519"
        const pubKey = await crypto.subtle.importKey(
            "jwk", normalizeJwkForImport(record.publicKeyJwk),
            { name: X25519_ALGORITHM },
            true, []
        );
        keyStore[record.name].publicKey = pubKey;
        keyStore[record.name].type = X25519_ALGORITHM;
        keyStore[record.name].curve = X25519_ALGORITHM; // 表示用
        keyStore[record.name].fingerprint = await calcFingerprint(pubKey);
      }
      if (record.privateKeyJwk && record.type === X25519_ALGORITHM) {
        const privKey = await crypto.subtle.importKey(
            "jwk", normalizeJwkForImport(record.privateKeyJwk),
            { name: X25519_ALGORITHM },
            true, ["deriveKey", "deriveBits"]
        );
        const raw = await crypto.subtle.exportKey("raw", keyStore[record.name].publicKey);
        const identifier = arrayBufferToBase64(raw);
        importedPrivateKeys.push({ name: record.name, identifier: identifier, cryptoKey: privKey, type: X25519_ALGORITHM });
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

// P-521用インポート（既存）
async function importPublicKeyFromXmlEC(xmlDoc, fileName, curve) {
  const x = getXmlTagContent(xmlDoc, "X");
  const y = getXmlTagContent(xmlDoc, "Y");
  if (!x || !y) throw new Error("X or Y not found in Public Key XML");
  
  const jwk = { kty: "EC", crv: curve, x: x, y: y, ext: true };
  const cryptoKey = await crypto.subtle.importKey(
    "jwk", normalizeJwkForImport(jwk),
    { name: EC_ALGORITHM, namedCurve: curve },
    true, []
  );
  const raw = await crypto.subtle.exportKey("raw", cryptoKey);
  const identifier = arrayBufferToBase64(raw);
  const fingerprint = await calcFingerprint(cryptoKey);
  return { name: fileName, identifier: identifier, cryptoKey: cryptoKey, type: "EC", curve: curve, fingerprint: fingerprint };
}

// 【追加】 X25519用インポート
async function importPublicKeyFromXmlX25519(xmlDoc, fileName) {
    const x = getXmlTagContent(xmlDoc, "X");
    // X25519にY座標は不要
    if (!x) throw new Error("X not found in X25519 Public Key XML");

    const jwk = { kty: "OKP", crv: X25519_ALGORITHM, x: x, ext: true };
    const cryptoKey = await crypto.subtle.importKey(
        "jwk", normalizeJwkForImport(jwk),
        { name: X25519_ALGORITHM },
        true, []
    );
    const raw = await crypto.subtle.exportKey("raw", cryptoKey);
    const identifier = arrayBufferToBase64(raw);
    const fingerprint = await calcFingerprint(cryptoKey);
    return { name: fileName, identifier: identifier, cryptoKey: cryptoKey, type: X25519_ALGORITHM, curve: X25519_ALGORITHM, fingerprint: fingerprint };
}

async function importPrivateKeyFromXmlEC(xmlDoc, fileName, curve) {
  const x = getXmlTagContent(xmlDoc, "X");
  const y = getXmlTagContent(xmlDoc, "Y");
  const d = getXmlTagContent(xmlDoc, "D");
  if (!x || !y || !d) throw new Error("Required elements not found in Private Key XML");
  
  const jwkPrivate = { kty: "EC", crv: curve, x: x, y: y, d: d, ext: true };
  const privateCryptoKey = await crypto.subtle.importKey(
    "jwk", normalizeJwkForImport(jwkPrivate),
    { name: EC_ALGORITHM, namedCurve: curve },
    true, ["deriveKey", "deriveBits"]
  );
  const publicJwk = { kty: "EC", crv: curve, x: x, y: y, ext: true };
  const publicCryptoKey = await crypto.subtle.importKey(
    "jwk", normalizeJwkForImport(publicJwk),
    { name: EC_ALGORITHM, namedCurve: curve },
    true, []
  );
  const raw = await crypto.subtle.exportKey("raw", publicCryptoKey);
  const identifier = arrayBufferToBase64(raw);
  const fingerprint = await calcFingerprint(publicCryptoKey);
  return { name: fileName, identifier: identifier, publicKey: publicCryptoKey, privateKey: privateCryptoKey, type: "EC", curve: curve, fingerprint: fingerprint };
}

// 【追加】 X25519用秘密鍵インポート
async function importPrivateKeyFromXmlX25519(xmlDoc, fileName) {
    const x = getXmlTagContent(xmlDoc, "X");
    const d = getXmlTagContent(xmlDoc, "D");
    // Yは不要
    if (!x || !d) throw new Error("Required elements not found in X25519 Private Key XML");

    const jwkPrivate = { kty: "OKP", crv: X25519_ALGORITHM, x: x, d: d, ext: true };
    const privateCryptoKey = await crypto.subtle.importKey(
        "jwk", normalizeJwkForImport(jwkPrivate),
        { name: X25519_ALGORITHM },
        true, ["deriveKey", "deriveBits"]
    );
    const publicJwk = { kty: "OKP", crv: X25519_ALGORITHM, x: x, ext: true };
    const publicCryptoKey = await crypto.subtle.importKey(
        "jwk", normalizeJwkForImport(publicJwk),
        { name: X25519_ALGORITHM },
        true, []
    );
    const raw = await crypto.subtle.exportKey("raw", publicCryptoKey);
    const identifier = arrayBufferToBase64(raw);
    const fingerprint = await calcFingerprint(publicCryptoKey);
    return { name: fileName, identifier: identifier, publicKey: publicCryptoKey, privateKey: privateCryptoKey, type: X25519_ALGORITHM, curve: X25519_ALGORITHM, fingerprint: fingerprint };
}

// 統合インポート関数
async function importPublicKeyFromXmlUnified(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const rootTag = xmlDoc.documentElement.tagName;
  
  if (rootTag === "ECKeyValue") {
    // Curveタグを確認して分岐
    const curve = getXmlTagContent(xmlDoc, "Curve") || DEFAULT_EC_CURVE;
    if (curve === X25519_ALGORITHM) {
        return await importPublicKeyFromXmlX25519(xmlDoc, fileName);
    } else {
        return await importPublicKeyFromXmlEC(xmlDoc, fileName, curve);
    }
  } else {
    throw new Error("Unknown Public Key XML format");
  }
}
async function importPrivateKeyFromXmlUnified(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const rootTag = xmlDoc.documentElement.tagName;

  if (rootTag === "ECKeyValue") {
    const curve = getXmlTagContent(xmlDoc, "Curve") || DEFAULT_EC_CURVE;
    if (curve === X25519_ALGORITHM) {
        return await importPrivateKeyFromXmlX25519(xmlDoc, fileName);
    } else {
        return await importPrivateKeyFromXmlEC(xmlDoc, fileName, curve);
    }
  } else {
    throw new Error("Unknown Private Key XML format");
  }
}

// ── ファイルの復号可能性チェック機能 ──
async function checkFileDecryptability(file) {
  try {
    const slice = file.slice(0, HEADER_CHECK_SIZE); 
    const buffer = await slice.arrayBuffer();
    const view = new DataView(buffer);
    const uint8 = new Uint8Array(buffer);
    
    let offset = 0;
    
    if (buffer.byteLength < 4) return { status: 'UNKNOWN', message: t('status_unknown') };
    const entryCount = readInt32LE(view, offset);
    offset += 4;

    if (entryCount < 0 || entryCount > 1000) {
      return { status: 'UNKNOWN', message: t('status_unencrypted') };
    }

    for (let i = 0; i < entryCount; i++) {
      if (offset >= buffer.byteLength) break;
      
      const type = uint8[offset];
      offset += 1;
      
      // Type 1: EC(P-521), Type 2: X25519
      if (type === ENTRY_TYPE_P521 || type === ENTRY_TYPE_X25519) { 
        if (offset + 4 > buffer.byteLength) break;
        const idLen = readInt32LE(view, offset);
        offset += 4;
        
        if (offset + idLen > buffer.byteLength) break;
        const recipientId = uint8.slice(offset, offset + idLen);
        const recipientIdB64 = arrayBufferToBase64(recipientId);
        offset += idLen;

        const matchedKey = importedPrivateKeys.find(k => k.identifier === recipientIdB64);
        if (matchedKey) {
          return { status: 'OK', keyName: matchedKey.name };
        }

        if (offset + 4 > buffer.byteLength) break;
        const ephLen = readInt32LE(view, offset);
        offset += 4 + ephLen;

        if (offset + 4 > buffer.byteLength) break;
        const wrapLen = readInt32LE(view, offset);
        offset += 4 + wrapLen;
      } else {
        return { status: 'UNKNOWN', message: t('status_unknown_type') };
      }
    }
    
    return { status: 'NO_KEY' };
    
  } catch (e) {
    console.error(e);
    return { status: 'UNKNOWN', message: t('status_parse_err') };
  }
}

// ── ファイルドラッグ＆ドロップ／選択処理 ──
const fileDropArea = document.getElementById('fileDropArea');
const fileListElem = document.getElementById('fileList');

async function addFilesToList(files) {
  for (let file of files) {
    filesToProcess.push(file);
    const li = document.createElement('li');
    
    const nameSpan = document.createElement('span');
    nameSpan.textContent = file.name;
    nameSpan.style.fontWeight = 'bold';
    li.appendChild(nameSpan);

    const statusSpan = document.createElement('span');
    statusSpan.style.marginLeft = '10px';
    statusSpan.style.fontSize = '0.9em';
    statusSpan.style.color = '#777';
    statusSpan.textContent = ' ⏳ ' + t('checking');
    li.appendChild(statusSpan);

    fileListElem.appendChild(li);

    checkFileDecryptability(file).then(result => {
      statusSpan.textContent = ""; 
      
      if (result.status === 'OK') {
        statusSpan.style.color = '#2e7d32'; 
        statusSpan.textContent = ` ✅ ${t('ok_decryptable')} (${t('col_keyname')}: ${result.keyName})`;
      } else if (result.status === 'NO_KEY') {
        statusSpan.style.color = '#c62828'; 
        statusSpan.textContent = ` ❌ ${t('ng_nokey')}`;
      } else {
        statusSpan.style.color = '#999';
        if (file.name.endsWith('.crypted')) {
            statusSpan.textContent = ` ⚠️ ${t('unknown_format')}`;
        }
      }
    });
  }
}

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
  addFilesToList(files);
});
document.getElementById('fileSelect').addEventListener('change', (e) => {
  const files = e.target.files;
  addFilesToList(files);
  e.target.value = "";
});

// ── 公開鍵ファイル入力 ──
/**
 * 公開鍵ファイル入力 (.pubkey XML) の処理
 * 読み込み時に確認キーを表示するように改修済み
 */
const pubKeyListElem = document.getElementById('pubKeyList');

document.getElementById('pubKeyInput').addEventListener('change', async (e) => {
  const files = e.target.files;
  
  for (let file of files) {
    const text = await file.text();
    try {
      // 1. XMLから公開鍵オブジェクトをインポート
      const pubKey = await importPublicKeyFromXmlUnified(text, file.name);
      
      // 2. 暗号化対象の鍵リスト（配列）に追加
      encryptionPublicKeys.push(pubKey);
      
      // 3. [改修箇所] 共通関数を使用して確認キー付きのUI要素を作成
      // 内部で calcConfirmationKey を呼び出し、4桁の数字を表示します
      const li = await createPubKeyListItem(pubKey);
      
      // 4. 暗号化セクションのリストへ追加
      pubKeyListElem.appendChild(li);
      
    } catch(err) {
      // エラーメッセージの多言語対応
      alert(t('alert_import_pub_err', { name: file.name }) + err.message);
    }
  }
  
  // 連続して同じファイルを選択できるようにリセット
  e.target.value = "";
});

// ── 秘密鍵ファイル入力 ──
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
        alert(t('alert_priv_exists', {name: keyName}));
        continue;
      }
      const keyPair = await importPrivateKeyFromXmlUnified(text, keyName);
      keyStore[keyPair.name] = { 
        publicKey: keyPair.publicKey, 
        privateKey: keyPair.privateKey, 
        type: keyPair.type,
        curve: keyPair.curve,
        fingerprint: keyPair.fingerprint 
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
      alert(t('alert_import_priv_err', {name: file.name}) + err.message);
    }
  }
  e.target.value = "";
  if(imported){
    alert(t('alert_import_priv_done'));
  }
  resetUI();
});

// ── ファイル暗号化処理 ──
async function encryptFile(file) {
  const aesKey = await crypto.subtle.generateKey(
    { name: AES_ALGORITHM, length: AES_KEY_LENGTH },
    true, ["encrypt", "decrypt"]
  );
  const aesKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
  // v2: ファイル単位の salt（HKDF）
  const fileNonce = window.crypto.getRandomValues(new Uint8Array(FILE_NONCE_LENGTH));
  const iv = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

  if (encryptionPublicKeys.length === 0) {
    throw new Error("No public key imported for encryption.");
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
    // ■ 分岐 1: 既存の EC (P-521)
    if (pub.type === "EC") {
      try {
        const ephemeralKeyPair = await crypto.subtle.generateKey(
          { name: EC_ALGORITHM, namedCurve: pub.curve },
          true, ["deriveBits"]
        );
        // v2: 共有秘密→HKDF→AES-GCM鍵（ヘッダ情報にバインド）
        const wrappingIV = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
        const ephemeralPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralKeyPair.publicKey));
        const recipientIdBytes = base64ToUint8Array(pub.identifier);
        const wrappingAAD = concatUint8Arrays([
          new Uint8Array([ENTRY_TYPE_P521]),
          writeInt32LE(recipientIdBytes.length),
          recipientIdBytes,
          writeInt32LE(ephemeralPubRaw.length),
          ephemeralPubRaw,
          wrappingIV,
          fileNonce
        ]);
        const wrappingInfo = await sha256Bytes(concatUint8Arrays([
          new TextEncoder().encode(HKDF_INFO_WRAP_PREFIX + "P-521"),
          wrappingAAD
        ]));
        const sharedSecret = await deriveSharedSecretBits(EC_ALGORITHM, ephemeralKeyPair.privateKey, pub.cryptoKey);
        const wrappingKey = await deriveAesGcmKeyFromSharedSecret(sharedSecret, fileNonce, wrappingInfo, ["encrypt", "decrypt"]);
        const wrappingCiphertextBuffer = await crypto.subtle.encrypt(
          { name: AES_ALGORITHM, iv: new Uint8Array(wrappingIV), additionalData: new Uint8Array(wrappingAAD) },
          wrappingKey,
          aesKeyRaw
        );
        const wrappingCiphertext = new Uint8Array(wrappingCiphertextBuffer);
        const wrappingOutput = concatUint8Arrays([wrappingIV, wrappingCiphertext]);
        
        entries.push({
          type: ENTRY_TYPE_P521, // Type 1
          recipientId: recipientIdBytes,
          ephemeralPub: ephemeralPubRaw,
          wrappingOutput: wrappingOutput
        });
      } catch (err) {
        console.error("EC Encrypt Fail: ", err);
      }
    } 
    // ■ 分岐 2: 新規 X25519
    else if (pub.type === X25519_ALGORITHM) {
        try {
            const ephemeralKeyPair = await crypto.subtle.generateKey(
              { name: X25519_ALGORITHM },
              true, ["deriveBits"]
            );
            const wrappingIV = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
            const ephemeralPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralKeyPair.publicKey));
            const recipientIdBytes = base64ToUint8Array(pub.identifier);
            const wrappingAAD = concatUint8Arrays([
              new Uint8Array([ENTRY_TYPE_X25519]),
              writeInt32LE(recipientIdBytes.length),
              recipientIdBytes,
              writeInt32LE(ephemeralPubRaw.length),
              ephemeralPubRaw,
              wrappingIV,
              fileNonce
            ]);
            const wrappingInfo = await sha256Bytes(concatUint8Arrays([
              new TextEncoder().encode(HKDF_INFO_WRAP_PREFIX + "X25519"),
              wrappingAAD
            ]));
            const sharedSecret = await deriveSharedSecretBits(X25519_ALGORITHM, ephemeralKeyPair.privateKey, pub.cryptoKey);
            const wrappingKey = await deriveAesGcmKeyFromSharedSecret(sharedSecret, fileNonce, wrappingInfo, ["encrypt", "decrypt"]);

            const wrappingCiphertextBuffer = await crypto.subtle.encrypt(
              { name: AES_ALGORITHM, iv: new Uint8Array(wrappingIV), additionalData: new Uint8Array(wrappingAAD) },
              wrappingKey,
              aesKeyRaw
            );
            const wrappingCiphertext = new Uint8Array(wrappingCiphertextBuffer);
            const wrappingOutput = concatUint8Arrays([wrappingIV, wrappingCiphertext]);

            entries.push({
              type: ENTRY_TYPE_X25519, // Type 2 (新規)
              recipientId: recipientIdBytes,
              ephemeralPub: ephemeralPubRaw,
              wrappingOutput: wrappingOutput
            });

        } catch(err) {
            console.error("X25519 Encrypt Fail: ", err);
        }
    }
  }
  
  if (entries.length === 0) {
    throw new Error("No valid public key available.");
  }
  
  const fileBuffer = new Uint8Array(await file.arrayBuffer());
  const fileNameBytes = encoder.encode(file.name);
  const payloadPlain = concatUint8Arrays([writeInt32LE(fileNameBytes.length), fileNameBytes, fileBuffer]);
  // v2: payload はヘッダ全体をAADにする（改ざん・取り違え検知）
  // まずヘッダ（entries + marker + fileNonce + iv）を組み立ててから暗号化する
  
  let parts = [];
  parts.push(writeInt32LE(entries.length));
  for (let entry of entries) {
    parts.push(new Uint8Array([entry.type]));
    if (entry.type === ENTRY_TYPE_P521 || entry.type === ENTRY_TYPE_X25519) {
      parts.push(writeInt32LE(entry.recipientId.length));
      parts.push(entry.recipientId);
      parts.push(writeInt32LE(entry.ephemeralPub.length));
      parts.push(entry.ephemeralPub);
      parts.push(writeInt32LE(entry.wrappingOutput.length));
      parts.push(entry.wrappingOutput);
    }
  }
  // v2 拡張: marker + fileNonce を iv の前に入れる
  parts.push(FILE_V2_MARKER);
  parts.push(fileNonce);
  parts.push(iv);

  const headerBytes = concatUint8Arrays(parts); // payloadEnc 以外の全ヘッダ
  const payloadInfo = await sha256Bytes(concatUint8Arrays([
    new TextEncoder().encode(HKDF_INFO_PAYLOAD_PREFIX),
    headerBytes
  ]));
  // payload鍵は既存のランダムAES鍵のまま。infoは将来の「鍵派生方式差し替え」用に予約（今はAADのみ効かせる）
  void payloadInfo; // lint回避（将来用）

  const payloadEnc = new Uint8Array(await crypto.subtle.encrypt(
    { name: AES_ALGORITHM, iv: new Uint8Array(iv), additionalData: new Uint8Array(headerBytes) },
    aesKey,
    payloadPlain
  ));

  parts.push(payloadEnc);
  const finalData = concatUint8Arrays(parts);
  const blob = new Blob([finalData], { type: "application/octet-stream" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = file.name + ".crypted";
  a.click();
}

// ── ファイル復号処理 ──
async function decryptFile(file) {
  try {
    if (importedPrivateKeys.length === 0) {
      throw new Error("No private key available for decryption.");
    }
    const fileBuffer = new Uint8Array(await file.arrayBuffer());
    const view = new DataView(fileBuffer.buffer);
    let offset = 0;
    if (fileBuffer.length < 4) {
      throw new Error("Invalid file.");
    }
    const entryCount = readInt32LE(view, offset);
    offset += 4;
    const headerEntries = [];
    const decoder = new TextDecoder();
    for (let i = 0; i < entryCount; i++) {
      const type = fileBuffer[offset];
      offset += 1;
      
      if (type === ENTRY_TYPE_P521 || type === ENTRY_TYPE_X25519) {
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
        headerEntries.push({ type: type, recipientId: recipientId, ephemeralPub: ephemeralPub, wrappingOutput: wrappingOutput });
      } else {
        throw new Error("Unknown key entry type.");
      }
    }
    // v2判定: entries の直後に marker がある場合は v2
    let isV2 = false;
    let fileNonce = null;
    if (offset + FILE_V2_MARKER.length <= fileBuffer.length) {
      const marker = fileBuffer.slice(offset, offset + FILE_V2_MARKER.length);
      if (eqBytes(marker, FILE_V2_MARKER)) {
        isV2 = true;
        offset += FILE_V2_MARKER.length;
        if (offset + FILE_NONCE_LENGTH + AES_IV_LENGTH > fileBuffer.length) {
          throw new Error("Invalid file.");
        }
        fileNonce = fileBuffer.slice(offset, offset + FILE_NONCE_LENGTH);
        offset += FILE_NONCE_LENGTH;
      }
    }
    if (offset + AES_IV_LENGTH > fileBuffer.length) {
      throw new Error("Invalid file.");
    }
    const iv = fileBuffer.slice(offset, offset + AES_IV_LENGTH);
    offset += AES_IV_LENGTH;
    const headerBytes = isV2 ? fileBuffer.slice(0, offset) : null;
    const payloadEnc = fileBuffer.slice(offset);
    let aesKeyRaw;
    let found = false;
    
    for (let entry of headerEntries) {
      const entryIdBase64 = arrayBufferToBase64(entry.recipientId);
      
      // ■ 分岐 1: Type 1 (EC P-521)
      if (entry.type === ENTRY_TYPE_P521) {
        for (let priv of importedPrivateKeys.filter(k => k.type === "EC")) {
          if (priv.identifier === entryIdBase64) {
            const ephemeralPubKey = await crypto.subtle.importKey(
              "raw", entry.ephemeralPub,
              { name: EC_ALGORITHM, namedCurve: keyStore[priv.name].curve },
              true, []
            );
            const wrappingIV = entry.wrappingOutput.slice(0, AES_IV_LENGTH);
            const wrappingCiphertext = entry.wrappingOutput.slice(AES_IV_LENGTH);
            try {
              let decrypted;
              if (isV2) {
                // v2: sharedSecret→HKDF で wrappingKey を作り、AAD を付与
                const recipientIdBytes = entry.recipientId;
                const wrappingAAD = concatUint8Arrays([
                  new Uint8Array([ENTRY_TYPE_P521]),
                  writeInt32LE(recipientIdBytes.length),
                  recipientIdBytes,
                  writeInt32LE(entry.ephemeralPub.length),
                  entry.ephemeralPub,
                  new Uint8Array(wrappingIV),
                  new Uint8Array(fileNonce)
                ]);
                const wrappingInfo = await sha256Bytes(concatUint8Arrays([
                  new TextEncoder().encode(HKDF_INFO_WRAP_PREFIX + "P-521"),
                  wrappingAAD
                ]));
                const sharedSecret = await deriveSharedSecretBits(EC_ALGORITHM, priv.cryptoKey, ephemeralPubKey);
                const wrappingKey = await deriveAesGcmKeyFromSharedSecret(sharedSecret, new Uint8Array(fileNonce), wrappingInfo, ["decrypt"]);
                decrypted = await crypto.subtle.decrypt(
                  { name: AES_ALGORITHM, iv: new Uint8Array(wrappingIV), additionalData: new Uint8Array(wrappingAAD) },
                  wrappingKey,
                  wrappingCiphertext
                );
              } else {
                // 旧: deriveKey + AADなし
                const wrappingKey = await crypto.subtle.deriveKey(
                  { name: EC_ALGORITHM, public: ephemeralPubKey },
                  priv.cryptoKey,
                  { name: AES_ALGORITHM, length: 256 },
                  false, ["decrypt"]
                );
                decrypted = await crypto.subtle.decrypt(
                  { name: AES_ALGORITHM, iv: wrappingIV },
                  wrappingKey,
                  wrappingCiphertext
                );
              }
              aesKeyRaw = new Uint8Array(decrypted);
              found = true;
              break;
            } catch (err) { }
          }
        }
      } 
      // ■ 分岐 2: Type 2 (X25519)
      else if (entry.type === ENTRY_TYPE_X25519) {
          for (let priv of importedPrivateKeys.filter(k => k.type === X25519_ALGORITHM)) {
              if (priv.identifier === entryIdBase64) {
                  const ephemeralPubKey = await crypto.subtle.importKey(
                      "raw", entry.ephemeralPub,
                      { name: X25519_ALGORITHM },
                      true, []
                  );
                  const wrappingIV = entry.wrappingOutput.slice(0, AES_IV_LENGTH);
                  const wrappingCiphertext = entry.wrappingOutput.slice(AES_IV_LENGTH);
                  try {
                      let decrypted;
                      if (isV2) {
                        const recipientIdBytes = entry.recipientId;
                        const wrappingAAD = concatUint8Arrays([
                          new Uint8Array([ENTRY_TYPE_X25519]),
                          writeInt32LE(recipientIdBytes.length),
                          recipientIdBytes,
                          writeInt32LE(entry.ephemeralPub.length),
                          entry.ephemeralPub,
                          new Uint8Array(wrappingIV),
                          new Uint8Array(fileNonce)
                        ]);
                        const wrappingInfo = await sha256Bytes(concatUint8Arrays([
                          new TextEncoder().encode(HKDF_INFO_WRAP_PREFIX + "X25519"),
                          wrappingAAD
                        ]));
                        const sharedSecret = await deriveSharedSecretBits(X25519_ALGORITHM, priv.cryptoKey, ephemeralPubKey);
                        const wrappingKey = await deriveAesGcmKeyFromSharedSecret(sharedSecret, new Uint8Array(fileNonce), wrappingInfo, ["decrypt"]);
                        decrypted = await crypto.subtle.decrypt(
                          { name: AES_ALGORITHM, iv: new Uint8Array(wrappingIV), additionalData: new Uint8Array(wrappingAAD) },
                          wrappingKey,
                          wrappingCiphertext
                        );
                      } else {
                        const wrappingKey = await crypto.subtle.deriveKey(
                          { name: X25519_ALGORITHM, public: ephemeralPubKey },
                          priv.cryptoKey,
                          { name: AES_ALGORITHM, length: 256 },
                          false, ["decrypt"]
                        );
                        decrypted = await crypto.subtle.decrypt(
                          { name: AES_ALGORITHM, iv: wrappingIV },
                          wrappingKey,
                          wrappingCiphertext
                        );
                      }
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
      throw new Error("Matching private key not found or AES decryption failed.");
    }
    const aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: AES_ALGORITHM }, true, ["decrypt"]);
    let payloadPlainBuffer;
    try {
      if (isV2) {
        payloadPlainBuffer = await crypto.subtle.decrypt(
          { name: AES_ALGORITHM, iv: new Uint8Array(iv), additionalData: new Uint8Array(headerBytes) },
          aesKey,
          payloadEnc
        );
      } else {
        payloadPlainBuffer = await crypto.subtle.decrypt({ name: AES_ALGORITHM, iv: iv }, aesKey, payloadEnc);
      }
    } catch (err) {
      throw new Error("AES decryption failed: " + err.message);
    }
    const payloadPlain = new Uint8Array(payloadPlainBuffer);
    const dv = new DataView(payloadPlain.buffer);
    if (payloadPlain.length < 4) {
      throw new Error("Decryption result is invalid.");
    }
    const fnameLen = dv.getInt32(0, true);
    if (4 + fnameLen > payloadPlain.length) {
      throw new Error("Decryption result is invalid.");
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
    throw err;
  }
}

// ── ボタン押下処理 ──
document.getElementById('encryptBtn').addEventListener('click', async () => {
  if (filesToProcess.length === 0) {
    alert(t('alert_no_file_enc'));
    return;
  }
  showSpinner(t('msg_enc_start'));
  let successCount = 0;
  let failCount = 0;

  for (let file of filesToProcess) {
    updateSpinnerText(t('msg_enc_processing', {name: file.name}));
    try {
      await encryptFile(file);
      successCount++;
    } catch (e) {
      console.error(e);
      failCount++;
    }
  }
  resetUIEncrypt();
  hideSpinner();

  if (successCount > 0) {
     showEncryptionSuccessUI(successCount);
  } else {
     alert(t('alert_done_result', {success: successCount, fail: failCount}));
  }
});

function showEncryptionSuccessUI(count) {
    const exportArea = document.getElementById("exportArea");
    clearExportArea();
    dispExportArea();

    const h3 = document.createElement("h3");
    h3.textContent = t('enc_success_title');
    h3.style.color = "#2e7d32";
    exportArea.appendChild(h3);

    const p = document.createElement("p");
    p.textContent = t('enc_success_msg', {count: count});
    exportArea.appendChild(p);
    
    exportArea.appendChild(document.createElement("hr"));

    const h4 = document.createElement("h4");
    h4.textContent = t('enc_next_step_title');
    exportArea.appendChild(h4);

    const desc = document.createElement("p");
    desc.textContent = t('enc_next_step_desc');
    desc.style.fontSize = "0.9em";
    desc.style.color = "#666";
    exportArea.appendChild(desc);

    const decryptUrl = `${PUBKEY_SHARE_BASE_URL}#${DECRYPT_MODE_HASH}`;
    
    const templateText = t('email_template_body', {
        url: decryptUrl
    });

    const textarea = document.createElement("textarea");
    textarea.rows = 8;
    textarea.style.width = "98%";
    textarea.value = templateText;
    exportArea.appendChild(textarea);

    const copyBtn = document.createElement("button");
    copyBtn.textContent = t('btn_copy_email');
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(templateText);
        copyBtn.textContent = t('copied');
    };
    exportArea.appendChild(copyBtn);
}

document.getElementById('decryptBtn').addEventListener('click', async () => {
  if (filesToProcess.length === 0) {
    alert(t('alert_no_file_dec'));
    return;
  }
  showSpinner(t('msg_dec_start'));
  let successCount = 0;
  let failCount = 0;

  for (let file of filesToProcess) {
    updateSpinnerText(t('msg_dec_processing', {name: file.name}));
    try {
      await decryptFile(file);
      successCount++;
    } catch (e) {
      console.error(e);
      failCount++;
    }
  }
  
  filesToProcess.length = 0;
  document.getElementById('fileList').textContent = "";
  document.getElementById('fileSelect').value = "";
  
  hideSpinner();
  alert(t('alert_done_result', {success: successCount, fail: failCount}));
});

// ── 鍵生成 ──
async function generateKeyPair(name, algType) {
  // ■ 分岐 1: 既存の P-521 (algType="EC")
  if (algType === "EC") {
    try {
      const keyPair = await crypto.subtle.generateKey(
        { name: EC_ALGORITHM, namedCurve: DEFAULT_EC_CURVE },
        true, ["deriveKey", "deriveBits"]
      );
      const fingerprint = await calcFingerprint(keyPair.publicKey);
      keyStore[name] = { 
        publicKey: keyPair.publicKey, 
        privateKey: keyPair.privateKey, 
        type: "EC",
        curve: DEFAULT_EC_CURVE,
        fingerprint: fingerprint
      };
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      await storeKeyPair(name, "EC", publicJwk, privateJwk);
      const raw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
      const identifier = arrayBufferToBase64(raw);
      importedPrivateKeys.push({ name: name, identifier: identifier, cryptoKey: keyPair.privateKey, type: "EC" });
      alert(t('alert_ec_gen_done', {name: name}));
      refreshKeyList();
    } catch (e) {
      console.error(e);
      alert(t('alert_ec_gen_err') + e);
    }
  } 
  // ■ 分岐 2: 新規 X25519
  else if (algType === X25519_ALGORITHM) {
      try {
        const keyPair = await crypto.subtle.generateKey(
            { name: X25519_ALGORITHM },
            true, ["deriveKey", "deriveBits"]
        );
        const fingerprint = await calcFingerprint(keyPair.publicKey);
        keyStore[name] = {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey,
            type: X25519_ALGORITHM,
            curve: X25519_ALGORITHM,
            fingerprint: fingerprint
        };
        const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
        const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
        await storeKeyPair(name, X25519_ALGORITHM, publicJwk, privateJwk);
        
        const raw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
        const identifier = arrayBufferToBase64(raw);
        importedPrivateKeys.push({ name: name, identifier: identifier, cryptoKey: keyPair.privateKey, type: X25519_ALGORITHM });
        alert(t('alert_ec_gen_done', {name: name}));
        refreshKeyList();
      } catch (e) {
        console.error(e);
        alert(t('alert_ec_gen_err') + e);
      }
  }
  else {
    alert(t('alert_unsupported_alg'));
  }
}

// ── 公開鍵URL共有機能 ──
async function exportPubkeyUrl(name) {
    const keyPair = keyStore[name];
    if (!keyPair || !keyPair.publicKey) {
        alert(t('alert_pub_not_found'));
        return;
    }

    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const xml = convertPublicJwkToXml(jwk); // X25519対応済み
    const utf8 = new TextEncoder().encode(xml);
    const b64 = btoa(String.fromCharCode(...utf8));
    const b64url = base64ToBase64Url(b64);
    
    const fingerprint = keyPair.fingerprint;
    const url = `${PUBKEY_SHARE_BASE_URL}#pubkey=${b64url}&fp=${fingerprint}`;

    const exportArea = document.getElementById("exportArea");
    clearExportArea();
    dispExportArea();

    const h3 = document.createElement("h3");
    h3.textContent = t('label_pub_url', {name: name});
    exportArea.appendChild(h3);

    const input = document.createElement("input");
    input.type = "text";
    input.value = url;
    input.readOnly = true;
    input.style.width = "98%";
    exportArea.appendChild(input);
    exportArea.appendChild(document.createElement("br"));

    const button = document.createElement("button");
    button.textContent = t('btn_copy_url');
    button.addEventListener("click", () => {
        navigator.clipboard.writeText(url);
        button.textContent = t('copied');
    });
    exportArea.appendChild(button);

    const p = document.createElement("p");
    p.textContent = t('label_pub_url_desc');
    exportArea.appendChild(p);
}

// ── 鍵一覧の再表示 ──
/**
 * 鍵一覧の再表示 (非同期版)
 * 確認キー (SAS: Short Authentication String) を目立たせる改修済み
 */
async function refreshKeyList() {
  const tbody = document.getElementById("keyTable").querySelector("tbody");
  tbody.textContent = ""; // テーブルの初期化

  for (const name in keyStore) {
    const tr = document.createElement("tr");

    // 1. 鍵名カラム
    const tdName = document.createElement("td");
    tdName.textContent = name;
    tr.appendChild(tdName);

    // 2. 種別カラム (表示用の分かりやすい名称に変換)
    const tdType = document.createElement("td");
    if (keyStore[name].type === "EC") {
        tdType.textContent = "ECDH (P-521)";
    } else if (keyStore[name].type === X25519_ALGORITHM) {
        tdType.textContent = "ECDH (X25519)";
    } else {
        tdType.textContent = keyStore[name].type;
    }
    tr.appendChild(tdType);

    // 3. 鍵情報カラム (ここを確認キー中心に改修)
    const tdKeyInfo = document.createElement("td");
    const fp = keyStore[name].fingerprint || "N/A";
    const confKey = await calcConfirmationKey(fp); // 4桁の数字を生成
    const curveName = keyStore[name].curve || "N/A";

    // --- [最優先] 確認キー (SAS) 表示エリア ---
    const confArea = document.createElement("div");
    confArea.style.textAlign = "center";
    confArea.style.padding = "4px";
    confArea.style.backgroundColor = "#f0f2fa";
    confArea.style.borderRadius = "8px";
    confArea.style.marginBottom = "8px";
    confArea.style.border = "1px solid var(--border)";
    
    confArea.innerHTML = `
      <div style="font-size: 0.75em; color: #666; margin-bottom: 2px;">${t('conf_key')}</div>
      <div style="font-size: 1.8em; font-weight: bold; color: var(--accent); letter-spacing: 3px;">${confKey}</div>
    `;

    // --- [補助] 詳細情報 (Curve名 & FP) 表示エリア ---
    const detailArea = document.createElement("div");
    detailArea.style.fontSize = "0.82em";
    detailArea.style.color = "#777";
    detailArea.style.lineHeight = "1.4";

    const curveInfo = document.createElement("div");
    curveInfo.textContent = `Curve: ${curveName}`;
    detailArea.appendChild(curveInfo);

    const fpInfo = document.createElement("div");
    fpInfo.style.marginTop = "2px";
    fpInfo.textContent = `FP: ${fp.substring(0, 12)}...`; // 先頭12文字のみ表示

    // フルFPコピーボタン
    const copyBtn = document.createElement("button");
    copyBtn.textContent = t('copy');
    copyBtn.style.marginLeft = "6px";
    copyBtn.style.fontSize = "0.85em";
    copyBtn.style.padding = "2px 6px";
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(fp);
        alert(t('copied'));
    };
    fpInfo.appendChild(copyBtn);
    detailArea.appendChild(fpInfo);

    tdKeyInfo.appendChild(confArea);
    tdKeyInfo.appendChild(detailArea);
    tr.appendChild(tdKeyInfo);

    // 4. 操作カラム
    const tdOps = document.createElement("td");

    // 公開鍵エクスポート
    const exportPubBtn = document.createElement("button");
    exportPubBtn.textContent = t('export_pub');
    exportPubBtn.onclick = () => exportKey(name, "public");

    // URLで共有
    const exportPubUrlBtn = document.createElement("button");
    exportPubUrlBtn.textContent = t('share_url');
    exportPubUrlBtn.onclick = () => exportPubkeyUrl(name);

    // 秘密鍵エクスポート (危険操作)
    const exportPrivBtn = document.createElement("button");
    exportPrivBtn.textContent = t('export_priv');
    exportPrivBtn.classList.add('export-privkey-btn');
    exportPrivBtn.onclick = () => {
      if (confirm(t('confirm_priv_export'))) {
        exportKey(name, "private");
      }
    };

    // 削除ボタン
    const deleteBtn = document.createElement("button");
    deleteBtn.textContent = t('delete');
    deleteBtn.onclick = () => deleteKey(name);

    // カラムへの追加
    tdOps.appendChild(exportPubBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(exportPubUrlBtn);
    tdOps.appendChild(document.createElement("br")); // 視認性向上のため改行
    tdOps.appendChild(exportPrivBtn);
    tdOps.appendChild(document.createTextNode(" "));
    tdOps.appendChild(deleteBtn);
    tr.appendChild(tdOps);

    tbody.appendChild(tr);
  }
}

// ── 鍵エクスポート ──
function convertPublicJwkToXml(jwk) {
  if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y></ECKeyValue>`;
  } else if (jwk.kty === "OKP" && jwk.crv === X25519_ALGORITHM) {
    // X25519は Yなし
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X></ECKeyValue>`;
  }
}
function convertPrivateJwkToXml(jwk) {
  if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y><D>${jwk.d}</D></ECKeyValue>`;
  } else if (jwk.kty === "OKP" && jwk.crv === X25519_ALGORITHM) {
    // X25519は Yなし
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><D>${jwk.d}</D></ECKeyValue>`;
  }
}

async function exportKey(name, type) {
  const keyPair = keyStore[name];
  let key;
  if (type === "public") {
    if (!keyPair.publicKey) { alert(t('err_no_pub_exists')); return; }
    key = keyPair.publicKey;
  } else if (type === "private") {
    if (!keyPair.privateKey) { alert(t('err_no_priv_exists')); return; }
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
    clearExportArea();
    dispExportArea();
    
    const h3 = document.createElement("h3");
    if (type === "private") {
      h3.textContent = t('header_export_priv', {name: name});
      exportArea.appendChild(h3);
      
      const p = document.createElement("p");
      p.style.color = "red";
      p.style.fontWeight = "bold";
      p.textContent = t('warn_priv_sensitive');
      exportArea.appendChild(p);
    } else {
      h3.textContent = t('header_export_pub', {name: name});
      exportArea.appendChild(h3);
    }
    
    const textarea = document.createElement("textarea");
    textarea.rows = 10;
    textarea.value = xml;
    exportArea.appendChild(textarea);

    const blob = new Blob([xml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);

    const downloadBtn = document.createElement("button");
    downloadBtn.textContent = (type === "public" ? t('btn_download_pub') : t('btn_download_priv'));
    downloadBtn.style.marginTop = "8px";
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
    alert(t('err_export_fail') + e);
  }
}

async function deleteKey(name) {
  if (!confirm(t('confirm_delete', {name: name}))) return;
  try {
    await deleteKeyRecord(name);
  } catch (e) {
    console.error("DB削除エラー", e);
  }
  delete keyStore[name];
  let privIndex = importedPrivateKeys.findIndex(k => k.name === name);
  if (privIndex >= 0) { importedPrivateKeys.splice(privIndex, 1); }
  alert(t('alert_deleted', {name: name}));
  clearExportArea();
  refreshKeyList();
}
document.getElementById("generateKeyButton").addEventListener("click", async function() {
  const keyName = document.getElementById("keyNameInput").value.trim();
  const regex = /^[A-Za-z0-9_\-@\.]+$/;
  if (!regex.test(keyName)) {
    alert(t('alert_keyname_invalid'));
    return;
  }
  if (keyStore[keyName]) {
    alert(t('alert_keyname_exists'));
    return;
  }
  const algSelect = document.getElementById("keyAlgorithmSelect");
  const algType = algSelect.value;
  await generateKeyPair(keyName, algType);
});

// ── IndexedDB初期化（リセット） ──
function resetDatabase() {
  if (!confirm(t('confirm_reset_db'))) return;
  if (db) { db.close(); }
  const req = indexedDB.deleteDatabase("PubliCryptDB");
  req.onsuccess = function() {
    alert(t('alert_reset_done'));
    for (let key in keyStore) { delete keyStore[key]; }
    importedPrivateKeys.length = 0;
    clearExportArea();
    db = null;
    refreshKeyList();
    initDB();
  };
  req.onerror = function(e) {
    alert(t('alert_reset_err'));
  };
  req.onblocked = function(e) {
    alert(t('alert_blocked'));
  };
}
document.getElementById('resetDBBtn').addEventListener('click', resetDatabase);

// ── ページ起動時: #pubkey= で公開鍵を読み込む ──
function setBlocksDisplay(ids, displayStyle) {
  ids.forEach(id => {
    let el = document.getElementById(id);
    if (el) {
      el.style.display = displayStyle;
    } else {
      let classElems = document.getElementsByClassName(id);
      for (let i = 0; i < classElems.length; i++) {
        classElems[i].style.display = displayStyle;
      }
    }
  });
}

/**
 * 暗号化セクションの公開鍵リスト用アイテム (li) を作成する
 */
async function createPubKeyListItem(pubKey) {
  const li = document.createElement('li');
  li.style.padding = "10px";
  li.style.borderBottom = "1px solid #eee";
  li.style.listStyle = "none";

  const confKey = await calcConfirmationKey(pubKey.fingerprint);

  // 確認キーを大きく表示
  const confArea = document.createElement('div');
  confArea.style.display = "flex";
  confArea.style.alignItems = "center";
  confArea.style.gap = "10px";
  confArea.innerHTML = `
    <span style="font-size:0.75em; color:#666;">${t('conf_key_short')}:</span>
    <span style="font-size:1.4em; font-weight:bold; color:var(--accent);">${confKey}</span>
  `;

  // 鍵名とFP（詳細）
  const infoArea = document.createElement('div');
  infoArea.style.fontSize = "0.85em";
  infoArea.style.color = "#555";
  infoArea.innerHTML = `<strong>${pubKey.name}</strong> <span style="color:#999;">(${pubKey.type})</span>`;

  const fpSpan = document.createElement('div');
  fpSpan.style.fontSize = "0.8em";
  fpSpan.style.color = "#999";
  fpSpan.textContent = `FP: ${pubKey.fingerprint.substring(0, 12)}...`;

  const copyBtn = document.createElement('button');
  copyBtn.textContent = t('copy');
  copyBtn.style.fontSize = "0.8em";
  copyBtn.style.padding = "2px 5px";
  copyBtn.style.marginLeft = "8px";
  copyBtn.onclick = () => {
      navigator.clipboard.writeText(pubKey.fingerprint);
      alert(t('copied'));
  };

  li.appendChild(confArea);
  li.appendChild(infoArea);
  infoArea.appendChild(fpSpan);
  fpSpan.appendChild(copyBtn);

  return li;
}

/**
 * ページ起動時: URLハッシュから公開鍵を読み込む
 * 確認キー（SAS）の計算とUI表示への統合済み
 */
async function tryLoadPubkeyFromHash() {
  if (location.hash.startsWith("#pubkey=")) {
    try {
      let hash = location.hash.slice(1);
      // URLSearchParamsでパース（&が含まれる場合を考慮）
      let params = new URLSearchParams(hash.replace(/&/g, '&'));
      let b64url = params.get('pubkey');
      let expectedFp = params.get('fp');

      if (!b64url) throw "Public key data not found";

      // Base64Url形式からXML文字列へデコード
      const b64 = base64UrlToBase64(b64url);
      const bin = atob(b64);
      const uint8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; ++i) uint8[i] = bin.charCodeAt(i);
      const xml = new TextDecoder().decode(uint8);

      // 公開鍵としてインポート
      const pubKey = await importPublicKeyFromXmlUnified(xml, "URL受信公開鍵");
      encryptionPublicKeys.push(pubKey);

      // フィンガープリントの一致確認
      if (expectedFp && pubKey.fingerprint !== expectedFp) {
        // 不一致の場合は警告を表示
        alert(t('alert_url_pub_mismatch', {
          expected: expectedFp, 
          actual: pubKey.fingerprint
        }));
      } else {
        // --- [改修箇所] 確認キーの算出とリスト表示 ---
        const confKey = await calcConfirmationKey(pubKey.fingerprint);

        // 暗号化セクションのリストにアイテムを追加
        const li = await createPubKeyListItem(pubKey);
        document.getElementById('pubKeyList').appendChild(li);

        // 成功通知と確認キーの強調表示
        alert(`✅ ${t('alert_url_pub_ok', { fp: pubKey.fingerprint })}\n\n` +
              `--------------------------\n` +
              `【 ${t('conf_key')}: ${confKey} 】\n` +
              `--------------------------\n` +
              `相手が提示した数字と一致することを確認してください。`);

        // 受信専用モードとして、不要なUIブロックを非表示にする
        setBlocksDisplay(HIDEABLE_UI_BLOCK_IDS, "none");
      }
    } catch (e) {
      alert(t('alert_url_load_err') + e);
    }
  }
}

// ── マジックリンク機能 ──
function createMagicLink() {
  const fragment = `${MAGIC_REQ_PARAM}=1`;
  const fullUrl = `${PUBKEY_SHARE_BASE_URL}#${fragment}`;

  const exportArea = document.getElementById("exportArea");
  clearExportArea();
  dispExportArea();

  const h3 = document.createElement("h3");
  h3.textContent = t('magic_link_header');
  exportArea.appendChild(h3);

  const p = document.createElement("p");
  p.textContent = t('magic_link_desc');
  exportArea.appendChild(p);

  const input = document.createElement("input");
  input.type = "text";
  input.value = fullUrl;
  input.readOnly = true;
  input.style.width = "98%";
  exportArea.appendChild(input);

  const button = document.createElement("button");
  button.textContent = t('btn_copy_request_url'); 
  button.addEventListener("click", () => {
      navigator.clipboard.writeText(fullUrl);
      button.textContent = t('copied');
  });
  exportArea.appendChild(button);
}

/**
 * マジックリンク受け取り側（ウィザード画面）の処理
 * 確認キーの表示機能を追加
 */
async function checkMagicLinkRequest() {
  if (!location.hash.includes(`${MAGIC_REQ_PARAM}=1`)) return;

  const mainApp = document.getElementById('main-app-container');
  if(mainApp) mainApp.style.display = 'none';
  
  const wizard = document.getElementById('magicLinkWizard');
  wizard.style.display = 'block';

  const reloadBtn = document.getElementById('reloadURLBtn');
  if (reloadBtn) reloadBtn.style.display = 'none';

  document.getElementById('wizardTitle').textContent = t('wizard_title');
  document.getElementById('wizardDesc').innerHTML = t('wizard_desc');
  
  const startBtn = document.getElementById('wizardStartBtn');
  startBtn.textContent = t('wizard_btn_start');

  startBtn.onclick = async () => {
    startBtn.disabled = true;
    startBtn.textContent = t('processing');

    try {
      const now = new Date();
      const keyName = `Guest_${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,'0')}${now.getDate().toString().padStart(2,'0')}_${now.getHours().toString().padStart(2,'0')}${now.getMinutes().toString().padStart(2,'0')}`;
      
      // 鍵ペア生成
      await generateKeyPair(keyName, X25519_ALGORITHM); 
      
      const keyPair = keyStore[keyName];
      const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const xml = convertPublicJwkToXml(jwk);
      const utf8 = new TextEncoder().encode(xml);
      const b64 = btoa(String.fromCharCode(...utf8));
      const b64url = base64ToBase64Url(b64);
      const fingerprint = keyPair.fingerprint;

      // --- [追加] 確認キーの派生 ---
      const confKey = await calcConfirmationKey(fingerprint);

      const replyUrl = `${PUBKEY_SHARE_BASE_URL}#pubkey=${b64url}&fp=${fingerprint}`;

      document.getElementById('wizardStep1').style.display = 'none';
      const resultArea = document.getElementById('wizardResult');
      resultArea.style.display = 'block';
      
      document.getElementById('wizardDoneMsg').textContent = t('wizard_step_done');

      // --- [追加] UIへの確認キー表示 ---
      let confKeyDisplay = document.getElementById('wizardConfKeyDisplay');
      if (!confKeyDisplay) {
          confKeyDisplay = document.createElement('div');
          confKeyDisplay.id = 'wizardConfKeyDisplay';
          confKeyDisplay.style.margin = "20px auto";
          confKeyDisplay.style.padding = "15px";
          confKeyDisplay.style.background = "#fff";
          confKeyDisplay.style.borderRadius = "12px";
          confKeyDisplay.style.border = "2px solid var(--accent)";
          confKeyDisplay.style.maxWidth = "200px";
          confKeyDisplay.style.boxShadow = "0 2px 8px rgba(0,0,0,0.05)";
          // 説明文の前に挿入
          resultArea.insertBefore(confKeyDisplay, document.getElementById('wizardReplyInst'));
      }
      confKeyDisplay.innerHTML = `
        <div style="font-size:0.85em; color:#666; margin-bottom:5px;">${t('conf_key')}</div>
        <div style="font-size:2.2em; font-weight:bold; color:var(--accent); letter-spacing:5px;">${confKey}</div>
      `;
      
      document.getElementById('wizardReplyInst').textContent = t('wizard_reply_inst');
      
      const replyInput = document.getElementById('wizardReplyUrl');
      replyInput.value = replyUrl;
      
      const copyBtn = document.getElementById('wizardCopyBtn');
      copyBtn.textContent = t('btn_copy_reply_url');
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(replyUrl);
        copyBtn.textContent = t('copied');
      };

    } catch (e) {
      console.error(e);
      alert("Error: " + e);
      startBtn.disabled = false;
    }
  };
}


// ── 復号誘導モード ──
function checkDecryptMode() {
  if (location.hash.includes(DECRYPT_MODE_HASH)) {
    const sectionsToHide = [
      'encryptSection',
      'pubkey-file-select-block',
      'privKeyImport',            
      'keyManagement',            
      'resetSection',             
      'magicLinkSection'
    ];
    setBlocksDisplay(sectionsToHide, "none");

    const reloadBtn = document.getElementById('reloadURLBtn');
    if (reloadBtn) reloadBtn.style.display = 'none';

    const encryptBtn = document.getElementById('encryptBtn');
    if(encryptBtn) encryptBtn.style.display = 'none';
    
    document.querySelector('h1').innerText = "PubliCrypt (復号)";
    
    const fileSectionHead = document.querySelector('#fileSection h2');
    if(fileSectionHead) fileSectionHead.innerHTML = t('decrypt_mode_title');

    const dropArea = document.getElementById('fileDropArea');
    dropArea.innerHTML = t('drop_area_text') + "<br><small>" + t('decrypt_mode_desc') + "</small>";
    
    const decryptBlock = document.querySelector('.decrypt-block');
    if(decryptBlock) {
        decryptBlock.style.display = 'block';
        decryptBlock.style.width = '100%';
    }
    
    const btn = document.getElementById('decryptBtn');
    btn.style.width = "100%";
    btn.style.fontSize = "1.2em";
    btn.style.marginTop = "20px";
  }
}

// ── 初期化処理 ──
window.addEventListener("load", async () => {
  const userLang = (navigator.language || navigator.userLanguage).toLowerCase(); 
  if (userLang.startsWith('ja')) {
      currentLang = 'ja';
  } else if (userLang.startsWith('fr')) {
      currentLang = 'fr';
  } else if (userLang.startsWith('lb')) {
      currentLang = 'lb';
  } else {
      currentLang = 'en';
  }
  updateUIText(); 

  await initDB();
  await tryLoadPubkeyFromHash();
  await checkMagicLinkRequest();
  checkDecryptMode();
});

// イベントリスナー
['ja', 'en', 'fr', 'lb'].forEach(lang => {
    const el = document.getElementById(`lang-${lang}`);
    if(el) el.addEventListener('click', () => changeLanguage(lang));
});

document.getElementById('resetUiBtn').addEventListener('click', async () => {
  resetUI();
});
document.getElementById('reloadURLBtn').addEventListener('click', async () => {
  const savedHash = location.hash;
  resetUI();
  if (savedHash) {
      history.replaceState(null, null, savedHash); 
  }
  await tryLoadPubkeyFromHash();
});

const magicLinkBtn = document.getElementById('createMagicLinkBtn');
if(magicLinkBtn) {
    magicLinkBtn.addEventListener('click', createMagicLink);
}

window.addEventListener("DOMContentLoaded", hideResetUiButtonsInExtension);
