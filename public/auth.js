'use strict';

// https://stackoverflow.com/questions/38987784/how-to-convert-a-hexadecimal-string-to-uint8array-and-back-in-javascript
function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuffer(hexstring) {
  return new Uint8Array(hexstring.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// set error on login/registration form
function error(msg) {
  $('#error').text(msg);
}

async function generatePublicKeys(encKey, hmacKey) {
  const enc = new TextEncoder();
  /* generate the keys we will upload */
  const rsaKeyPairPromise = crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  const ecdsaKeyPairPromise = crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-384"
    },
    true,
    ["sign", "verify"]
  );

  const rsaPair   = await rsaKeyPairPromise;
  const ecdsaPair = await ecdsaKeyPairPromise;

  const rsaPrivateKey = await crypto.subtle.exportKey('jwk', await rsaPair.privateKey);
  const ecdsaPrivateKey = await crypto.subtle.exportKey('jwk', await ecdsaPair.privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ivHex = bufferToHex(iv);

  const encryptedKeys = bufferToHex(await crypto.subtle.encrypt({
      name: 'AES-CBC',
      iv: iv
    },
    encKey,
    enc.encode(JSON.stringify({rsa: rsaPrivateKey, ecdsa: ecdsaPrivateKey}))
  ));
  const hmac = await crypto.subtle.sign("HMAC", hmacKey, enc.encode(encryptedKeys+ivHex));

  return { 
    rsaPublicKey:   await crypto.subtle.exportKey('jwk', await rsaPair.publicKey), 
    ecdsaPublicKey: await crypto.subtle.exportKey('jwk', await ecdsaPair.publicKey),
    privateKeys: encryptedKeys,
    hmac: bufferToHex(hmac),
    iv: ivHex
  };
}

async function deriveSecrets(username, password) {
  const enc = new TextEncoder();

  /* generate our local keys */
  const salt = await crypto.subtle.digest('SHA-256', enc.encode(`INSECURE_CHAT-${username}`))
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']),
    256
  );
  const hkdfKey = await crypto.subtle.importKey("raw", bits, { name: "HKDF" }, false, ["deriveKey", "deriveBits"] );
  const authKey = crypto.subtle.deriveBits(
    {
        name: "HKDF",
        salt: salt,
        info: enc.encode("AUTH"),
        hash: 'SHA-256',
    },
    hkdfKey,
    256
  );
  const encKey = crypto.subtle.deriveKey(
    {
        name: "HKDF",
        salt: salt,
        info: enc.encode("ENCRYPT"),
        hash: 'SHA-256',
    },
    hkdfKey,
    {name: "AES-CBC", length: 256},
    false,
    [ "encrypt", "decrypt" ]
  );
  const hmacKey = crypto.subtle.deriveKey(
    {
        name: "HKDF",
        salt: salt,
        info: enc.encode("HMAC"),
        hash: 'SHA-256',
    },
    hkdfKey,
    {name: "HMAC", hash: "SHA-256", length: 256},
    false,
    [ "sign", "verify" ]
  );
  return { authKey: bufferToHex(await authKey),
           encKey: await encKey,
           hmacKey: await hmacKey };
}

async function decryptPrivateKeys(encKey, hmacKey, privateKeys, iv, mac) {
  const valid = await crypto.subtle.verify("HMAC", hmacKey, hexToBuffer(mac), new TextEncoder().encode(privateKeys+iv));
  if(!valid)
    return;
  const decrypted = JSON.parse(new TextDecoder().decode(
    await crypto.subtle.decrypt({ name: 'AES-CBC', iv: hexToBuffer(iv)}, encKey, hexToBuffer(privateKeys))));

  const signKey = crypto.subtle.importKey("jwk", decrypted.ecdsa, 
    {
      name: "ECDSA",
      namedCurve: "P-384"
    },
    false,
    ["sign"]
  );

  const privateKey = crypto.subtle.importKey("jwk", decrypted.rsa, 
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    false,
    ["decrypt"]
  );
  return {
    signKey: await signKey,
    privateKey: await privateKey
  };
}

async function check_password() {
  const token    = $('meta[name="csrf"]').attr('content');
  const username = $('#username').val();
  const password = $('#password').val();
  const confirm  = $('#confirm-password').val();
  if (username == '') {
    return error('Username required');
  } else if (password.length < 8) {
    return error('Password must be at least 8 characters long');
  } else if (password != confirm) {
    return error('Passwords do not match');
  }
  const secrets = await deriveSecrets(username, password);
  const publics = await generatePublicKeys(secrets.encKey, secrets.hmacKey);
  publics.username = username;
  publics.password = secrets.authKey;
  const fet = await (await fetch('/register', {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json;charset=utf-8',
      'CSRF-Token': token
    },
    method: 'POST',
    body: JSON.stringify(publics)
  })).json();
  console.log(fet);
  if (!fet.error) {
    $(location).attr('href', '/');
  } else {
    error(fet.error);
  }
}
