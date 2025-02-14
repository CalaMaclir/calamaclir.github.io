// common.js
"use strict";

// ── 定数 ──
export const RSA_ALGORITHM = "RSA-OAEP";
export const RSA_HASH = "SHA-256";
export const RSA_MODULUS_LENGTH = 4096;
export const EC_ALGORITHM = "ECDH";
export const DEFAULT_EC_CURVE = "P-521";
export const AES_ALGORITHM = "AES-GCM";
export const AES_KEY_LENGTH = 256;
export const AES_IV_LENGTH = 12;

// ── ユーティリティ関数 ──
export function base64UrlToBase64(url) {
  let b64 = url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) { b64 += '='; }
  return b64;
}

export function base64ToBase64Url(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let b of bytes) { binary += String.fromCharCode(b); }
  return btoa(binary);
}

export function writeInt32LE(val) {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setInt32(0, val, true);
  return new Uint8Array(buf);
}

export function readInt32LE(view, offset) {
  return view.getInt32(offset, true);
}

export function concatUint8Arrays(arrays) {
  let total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  let result = new Uint8Array(total);
  let offset = 0;
  arrays.forEach(arr => { result.set(arr, offset); offset += arr.length; });
  return result;
}

export function getRsaBitLengthFromXmlModulus(modulusBase64) {
  const binaryString = atob(modulusBase64);
  return binaryString.length * 8;
}

// ── IndexedDB 操作 ──
export let db = null;

export function initDB(callback) {
  const request = indexedDB.open("PubliCryptDB", 1);
  request.onupgradeneeded = function(e) {
    db = e.target.result;
    if (!db.objectStoreNames.contains("keys")) {
      db.createObjectStore("keys", { keyPath: "name" });
    }
  };
  request.onsuccess = function(e) {
    db = e.target.result;
    if (callback) callback();
  };
  request.onerror = function(e) {
    console.error("IndexedDB error", e);
  };
}

export function storeKeyRecord(record) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e);
  });
}

export function deleteKeyRecord(name) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readwrite");
    const store = transaction.objectStore("keys");
    const req = store.delete(name);
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e);
  });
}

export function getKeyRecord(name) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("keys", "readonly");
    const store = transaction.objectStore("keys");
    const req = store.get(name);
    req.onsuccess = () => resolve(req.result);
    req.onerror = (e) => reject(e);
  });
}

export async function storeKeyPair(name, type, publicJwk, privateJwk) {
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

// ── XML から鍵インポート関係 ──
export function getXmlTagContent(xmlDoc, tagName) {
  const el = xmlDoc.getElementsByTagName(tagName)[0];
  return el ? el.textContent.trim() : null;
}

// RSA 公開鍵インポート
export async function importPublicKeyFromXmlRSA(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const modulus = getXmlTagContent(xmlDoc, "Modulus");
  const exponent = getXmlTagContent(xmlDoc, "Exponent");
  if (!modulus || !exponent) {
    throw new Error("公開鍵XMLに Modulus または Exponent が見つかりません");
  }
  const n = base64ToBase64Url(modulus);
  const e = base64ToBase64Url(exponent);
  const jwk = { kty: "RSA", n: n, e: e, ext: true };
  const cryptoKey = await crypto.subtle.importKey(
    "jwk", jwk,
    { name: RSA_ALGORITHM, hash: RSA_HASH },
    true, ["encrypt"]
  );
  const bitLength = getRsaBitLengthFromXmlModulus(modulus);
  return { name: fileName, identifier: modulus, cryptoKey, type: "RSA", bitLength };
}

// RSA 秘密鍵インポート
export async function importPrivateKeyFromXmlRSA(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const modulus = getXmlTagContent(xmlDoc, "Modulus");
  const exponent = getXmlTagContent(xmlDoc, "Exponent");
  const d = getXmlTagContent(xmlDoc, "D");
  const p = getXmlTagContent(xmlDoc, "P");
  const q = getXmlTagContent(xmlDoc, "Q");
  const dp = getXmlTagContent(xmlDoc, "DP");
  const dq = getXmlTagContent(xmlDoc, "DQ");
  const inverseQ = getXmlTagContent(xmlDoc, "InverseQ");
  if (!modulus || !exponent || !d || !p || !q || !dp || !dq || !inverseQ) {
    throw new Error("秘密鍵XMLに必要な要素が見つかりません");
  }
  const jwkPrivate = {
    kty: "RSA",
    n: base64ToBase64Url(modulus),
    e: base64ToBase64Url(exponent),
    d: base64ToBase64Url(d),
    p: base64ToBase64Url(p),
    q: base64ToBase64Url(q),
    dp: base64ToBase64Url(dp),
    dq: base64ToBase64Url(dq),
    qi: base64ToBase64Url(inverseQ),
    ext: true
  };
  const privateCryptoKey = await crypto.subtle.importKey(
    "jwk", jwkPrivate,
    { name: RSA_ALGORITHM, hash: RSA_HASH },
    true, ["decrypt"]
  );
  const jwkPublic = {
    kty: "RSA",
    n: base64ToBase64Url(modulus),
    e: base64ToBase64Url(exponent),
    ext: true
  };
  const publicCryptoKey = await crypto.subtle.importKey(
    "jwk", jwkPublic,
    { name: RSA_ALGORITHM, hash: RSA_HASH },
    true, ["encrypt"]
  );
  const bitLength = getRsaBitLengthFromXmlModulus(modulus);
  return { name: fileName, identifier: modulus, publicKey: publicCryptoKey, privateKey: privateCryptoKey, type: "RSA", bitLength };
}

// EC 公開鍵インポート
export async function importPublicKeyFromXmlEC(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const x = getXmlTagContent(xmlDoc, "X");
  const y = getXmlTagContent(xmlDoc, "Y");
  const curve = getXmlTagContent(xmlDoc, "Curve") || DEFAULT_EC_CURVE;
  if (!x || !y) {
    throw new Error("公開鍵XMLに X または Y が見つかりません");
  }
  const jwk = { kty: "EC", crv: curve, x, y, ext: true };
  const cryptoKey = await crypto.subtle.importKey(
    "jwk", jwk,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, []
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", cryptoKey));
  const identifier = arrayBufferToBase64(raw);
  return { name: fileName, identifier, cryptoKey, type: "EC", curve };
}

// EC 秘密鍵インポート
export async function importPrivateKeyFromXmlEC(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const x = getXmlTagContent(xmlDoc, "X");
  const y = getXmlTagContent(xmlDoc, "Y");
  const d = getXmlTagContent(xmlDoc, "D");
  const curve = getXmlTagContent(xmlDoc, "Curve") || DEFAULT_EC_CURVE;
  if (!x || !y || !d) {
    throw new Error("秘密鍵XMLに必要な要素が見つかりません");
  }
  const jwkPrivate = { kty: "EC", crv: curve, x, y, d, ext: true };
  const privateCryptoKey = await crypto.subtle.importKey(
    "jwk", jwkPrivate,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, ["deriveKey"]
  );
  const publicJwk = { kty: "EC", crv: curve, x, y, ext: true };
  const publicCryptoKey = await crypto.subtle.importKey(
    "jwk", publicJwk,
    { name: EC_ALGORITHM, namedCurve: curve },
    true, []
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicCryptoKey));
  const identifier = arrayBufferToBase64(raw);
  return { name: fileName, identifier, publicKey: publicCryptoKey, privateKey: privateCryptoKey, type: "EC", curve };
}

// 統合版インポート（XML のルートタグで判別）
export async function importPublicKeyFromXmlUnified(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const rootTag = xmlDoc.documentElement.tagName;
  if (rootTag === "RSAKeyValue") {
    return await importPublicKeyFromXmlRSA(xmlString, fileName);
  } else if (rootTag === "ECKeyValue") {
    return await importPublicKeyFromXmlEC(xmlString, fileName);
  } else {
    throw new Error("公開鍵XMLの形式が不明です");
  }
}

export async function importPrivateKeyFromXmlUnified(xmlString, fileName) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "application/xml");
  const rootTag = xmlDoc.documentElement.tagName;
  if (rootTag === "RSAKeyValue") {
    return await importPrivateKeyFromXmlRSA(xmlString, fileName);
  } else if (rootTag === "ECKeyValue") {
    return await importPrivateKeyFromXmlEC(xmlString, fileName);
  } else {
    throw new Error("秘密鍵XMLの形式が不明です");
  }
}

// ── 暗号化／復号関数 ──
export async function encryptFile(file, encryptionPublicKeys) {
  // AES鍵生成
  const aesKey = await crypto.subtle.generateKey(
    { name: AES_ALGORITHM, length: AES_KEY_LENGTH },
    true, ["encrypt", "decrypt"]
  );
  const aesKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
  const iv = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

  if (encryptionPublicKeys.length === 0) {
    throw new Error("暗号化のための公開鍵がインポートされていません。");
  }

  // 重複除外処理
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
    if (pub.type === "RSA") {
      const encKeyBuffer = await crypto.subtle.encrypt({ name: RSA_ALGORITHM }, pub.cryptoKey, aesKeyRaw);
      const idBytes = encoder.encode(pub.identifier);
      entries.push({
        type: 0,
        identifier: idBytes,
        encryptedKey: new Uint8Array(encKeyBuffer)
      });
    } else if (pub.type === "EC") {
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
      const wrappingOutput = concatUint8Arrays([wrappingIV, new Uint8Array(wrappingCiphertextBuffer)]);
      const recipientIdBytes = Uint8Array.from(atob(pub.identifier), c => c.charCodeAt(0));
      entries.push({
        type: 1,
        recipientId: recipientIdBytes,
        ephemeralPub: ephemeralPubRaw,
        wrappingOutput
      });
    }
  }
  
  if (entries.length === 0) {
    throw new Error("有効な公開鍵がありません。");
  }

  // ファイルデータの読み込みとペイロード作成
  const fileBuffer = new Uint8Array(await file.arrayBuffer());
  const fileNameBytes = encoder.encode(file.name);
  const payloadPlain = concatUint8Arrays([writeInt32LE(fileNameBytes.length), fileNameBytes, fileBuffer]);
  const payloadEnc = new Uint8Array(await crypto.subtle.encrypt(
    { name: AES_ALGORITHM, iv },
    aesKey,
    payloadPlain
  ));
  
  let parts = [];
  parts.push(writeInt32LE(entries.length));
  for (let entry of entries) {
    parts.push(new Uint8Array([entry.type]));
    if (entry.type === 0) {
      parts.push(writeInt32LE(entry.identifier.length));
      parts.push(entry.identifier);
      parts.push(writeInt32LE(entry.encryptedKey.length));
      parts.push(entry.encryptedKey);
    } else if (entry.type === 1) {
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
  return new Blob([concatUint8Arrays(parts)], { type: "application/octet-stream" });
}

export async function decryptFile(file, importedPrivateKeys, keyStore) {
  const fileBuffer = new Uint8Array(await file.arrayBuffer());
  const view = new DataView(fileBuffer.buffer);
  let offset = 0;
  if (fileBuffer.length < 4) throw new Error("ファイルが不正です。");
  const entryCount = readInt32LE(view, offset);
  offset += 4;
  const headerEntries = [];
  const decoder = new TextDecoder();
  
  for (let i = 0; i < entryCount; i++) {
    const type = fileBuffer[offset];
    offset += 1;
    if (type === 0) {
      const idLen = readInt32LE(view, offset);
      offset += 4;
      const idBytes = fileBuffer.slice(offset, offset + idLen);
      offset += idLen;
      const encKeyLen = readInt32LE(view, offset);
      offset += 4;
      const encryptedKey = fileBuffer.slice(offset, offset + encKeyLen);
      offset += encKeyLen;
      headerEntries.push({ type: 0, identifier: decoder.decode(idBytes), encryptedKey });
    } else if (type === 1) {
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
      headerEntries.push({ type: 1, recipientId, ephemeralPub, wrappingOutput });
    } else {
      throw new Error("不明な鍵エントリータイプです。");
    }
  }
  
  if (offset + AES_IV_LENGTH > fileBuffer.length) throw new Error("ファイルが不正です。");
  const iv = fileBuffer.slice(offset, offset + AES_IV_LENGTH);
  offset += AES_IV_LENGTH;
  const payloadEnc = fileBuffer.slice(offset);
  let aesKeyRaw;
  let found = false;
  
  for (let entry of headerEntries) {
    if (entry.type === 0) {
      for (let priv of importedPrivateKeys.filter(k => k.type === "RSA")) {
        if (priv.identifier === entry.identifier) {
          try {
            aesKeyRaw = new Uint8Array(await crypto.subtle.decrypt({ name: RSA_ALGORITHM }, priv.cryptoKey, entry.encryptedKey));
            found = true;
            break;
          } catch (err) { }
        }
      }
    } else if (entry.type === 1) {
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
            const decrypted = await crypto.subtle.decrypt({ name: AES_ALGORITHM, iv: wrappingIV }, wrappingKey, wrappingCiphertext);
            aesKeyRaw = new Uint8Array(decrypted);
            found = true;
            break;
          } catch (err) { }
        }
      }
    }
    if (found) break;
  }
  
  if (!found || !aesKeyRaw) throw new Error("一致する秘密鍵が見つからないか、AES鍵の復号に失敗しました。");
  const aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: AES_ALGORITHM }, true, ["decrypt"]);
  let payloadPlainBuffer;
  try {
    payloadPlainBuffer = await crypto.subtle.decrypt({ name: AES_ALGORITHM, iv }, aesKey, payloadEnc);
  } catch (err) {
    throw new Error("AES復号に失敗しました: " + err.message);
  }
  const payloadPlain = new Uint8Array(payloadPlainBuffer);
  const dv = new DataView(payloadPlain.buffer);
  if (payloadPlain.length < 4) throw new Error("復号結果が不正です。");
  const fnameLen = dv.getInt32(0, true);
  if (4 + fnameLen > payloadPlain.length) throw new Error("復号結果が不正です。");
  const fnameBytes = payloadPlain.slice(4, 4 + fnameLen);
  const originalFileName = decoder.decode(fnameBytes);
  const fileContent = payloadPlain.slice(4 + fnameLen);
  return { fileName: originalFileName, fileContent };
}

// ── 鍵生成関数 ──
export async function generateKeyPair(name, algType, keyStore, importedPrivateKeys) {
  if (algType === "RSA") {
    const algorithm = {
      name: RSA_ALGORITHM,
      modulusLength: RSA_MODULUS_LENGTH,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: RSA_HASH
    };
    const keyPair = await crypto.subtle.generateKey(algorithm, true, ["encrypt", "decrypt"]);
    keyStore[name] = { 
      publicKey: keyPair.publicKey, 
      privateKey: keyPair.privateKey, 
      type: "RSA",
      bitLength: RSA_MODULUS_LENGTH
    };
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    await storeKeyPair(name, "RSA", publicJwk, privateJwk);
    const identifier = base64UrlToBase64(publicJwk.n);
    importedPrivateKeys.push({ name, identifier, cryptoKey: keyPair.privateKey, type: "RSA" });
    return keyStore[name];
  } else if (algType === "EC") {
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
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const identifier = arrayBufferToBase64(raw);
    importedPrivateKeys.push({ name, identifier, cryptoKey: keyPair.privateKey, type: "EC" });
    return keyStore[name];
  }
}

// ── 鍵エクスポート変換関数 ──
export function convertPublicJwkToXml(jwk) {
  if (jwk.kty === "RSA") {
    const modulus = base64UrlToBase64(jwk.n);
    const exponent = base64UrlToBase64(jwk.e);
    return `<RSAKeyValue><Modulus>${modulus}</Modulus><Exponent>${exponent}</Exponent></RSAKeyValue>`;
  } else if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y></ECKeyValue>`;
  }
}

export function convertPrivateJwkToXml(jwk) {
  if (jwk.kty === "RSA") {
    const modulus = base64UrlToBase64(jwk.n);
    const exponent = base64UrlToBase64(jwk.e);
    const d = base64UrlToBase64(jwk.d);
    const p = base64UrlToBase64(jwk.p);
    const q = base64UrlToBase64(jwk.q);
    const dp = base64UrlToBase64(jwk.dp);
    const dq = base64UrlToBase64(jwk.dq);
    const inverseQ = base64UrlToBase64(jwk.qi);
    return `<RSAKeyValue><Modulus>${modulus}</Modulus><Exponent>${exponent}</Exponent>` +
           `<P>${p}</P><Q>${q}</Q><DP>${dp}</DP><DQ>${dq}</DQ><InverseQ>${inverseQ}</InverseQ>` +
           `<D>${d}</D></RSAKeyValue>`;
  } else if (jwk.kty === "EC") {
    return `<ECKeyValue><Curve>${jwk.crv}</Curve><X>${jwk.x}</X><Y>${jwk.y}</Y><D>${jwk.d}</D></ECKeyValue>`;
  }
}

// ── UI ヘルパー ──
export function showSpinner() {
  const spinner = document.getElementById('spinner');
  if (spinner) spinner.style.display = 'block';
}

export function hideSpinner() {
  const spinner = document.getElementById('spinner');
  if (spinner) spinner.style.display = 'none';
}

export function clearExportArea() {
  const exportArea = document.getElementById("exportArea");
  if (exportArea) exportArea.innerHTML = "";
}

export function resetUI() {
  const fileListElem = document.getElementById('fileList');
  if (fileListElem) fileListElem.innerHTML = "";
  const fileDropArea = document.getElementById('fileDropArea');
  if (fileDropArea) fileDropArea.textContent = "ここにファイルをドロップ";
  hideSpinner();
}

// ── ファイルヘッダー解析（PubliCryptDisp 用） ──
export function parseFileHeader(buffer, importedPrivateKeys) {
  const fileBuffer = new Uint8Array(buffer);
  const view = new DataView(buffer);
  let offset = 0;
  const headerOutput = [];
  if (fileBuffer.length < 4) {
    headerOutput.push("ファイルが不正です。");
    return headerOutput;
  }
  const entryCount = readInt32LE(view, offset);
  offset += 4;
  const decoder = new TextDecoder();
  for (let i = 0; i < entryCount; i++) {
    const entryType = fileBuffer[offset];
    offset += 1;
    if (entryType === 0) {
      const idLen = readInt32LE(view, offset);
      offset += 4;
      const idBytes = fileBuffer.slice(offset, offset + idLen);
      offset += idLen;
      const encKeyLen = readInt32LE(view, offset);
      offset += 4;
      offset += encKeyLen;
      const identifier = decoder.decode(idBytes);
      headerOutput.push(`RSA エントリー - 識別子: ${identifier}`);
    } else if (entryType === 1) {
      const idLen = readInt32LE(view, offset);
      offset += 4;
      const recipientIdBytes = fileBuffer.slice(offset, offset + idLen);
      offset += idLen;
      const ephLen = readInt32LE(view, offset);
      offset += 4;
      offset += ephLen;
      const wrapLen = readInt32LE(view, offset);
      offset += 4;
      offset += wrapLen;
      const recipientIdStr = btoa(String.fromCharCode(...recipientIdBytes));
      headerOutput.push(`EC エントリー - 識別子: ${recipientIdStr}`);
    } else {
      headerOutput.push("不明なエントリータイプが含まれています。");
    }
  }
  return headerOutput;
}
