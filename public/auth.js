// https://stackoverflow.com/questions/38987784/how-to-convert-a-hexadecimal-string-to-uint8array-and-back-in-javascript
function bufferToHex (buffer) {
    return [...new Uint8Array (buffer)]
        .map (b => b.toString (16).padStart (2, "0"))
        .join ("");
}

function hexToBuffer (hexstring) {
    return new Uint8Array(hexstring.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// set error on login/registration form
function error(msg) {
    $('#error').text(msg);
}

// generate an RSA key pair
async function generateKeyPair() {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// derive a key from a password and a (string) salt with PBKDF2
async function deriveKeySalt(password, salt) {
    var enc = new TextEncoder();
    var keyMaterialPromise = window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );
    var saltPromise = window.crypto.subtle.digest("SHA-256", enc.encode(salt));
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: await saltPromise,
            iterations: 100000,
            hash: "SHA-256"
        },
        await keyMaterialPromise,
        { name: "AES-GCM", length: 256},
        true,
        [ "encrypt", "decrypt" ]
    );
}

// derive a key from a username and password
// this key will be used to encrypt/decrypt our generated private key
async function deriveKey(username, password) {
    return deriveKeySalt(password, "insecure-chat_" + username);
}

// generate a password from a username and password
// the password generated here will be presented to the server
// this way we do not share our actual password with the server
// and the server can prevent just anyone from retrieving our encrypted private key
async function getPassword(username, password) {
    var key = await deriveKeySalt(password, "insecure-chat_pwd_" + username);
    var exportedKey = await window.crypto.subtle.exportKey("raw", key);
    return bufferToHex(exportedKey);
}

// generate all the secrets we need at registration time
async function generateSecrets(username, password) {
    var deriveKeyPromise = deriveKey(username, password);
    var generateKeyPromise = generateKeyPair();
    var derivedKey = await deriveKeyPromise;
    var generatedKey = await generateKeyPromise;

    var publicKey = generatedKey.publicKey;
    var privateKey = generatedKey.privateKey;

    var exportedKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    iv = window.crypto.getRandomValues(new Uint8Array(12));
    var encryptedKey = await window.crypto.subtle.encrypt(
        {
        name: "AES-GCM",
        iv: iv
        },
        derivedKey,
        exportedKey
    );
    var exportPubKey = await window.crypto.subtle.exportKey("jwk", publicKey);
    
    return {
        username: username,
        password: await getPassword(username, password),
        publicKey: exportPubKey,
        privateKey: bufferToHex(encryptedKey),
        iv: bufferToHex(iv)
    };
}

// derive the secrets from a username and password
// used at login
async function deriveSecrets(username, password){
    var derivedKeyPromise = deriveKey(username, password);
    return {
        password: await getPassword(username, password),
        key: await derivedKeyPromise
    }
}

// used to decrypt the private key the server sends us
async function decryptPrivateKey(derivKey, encPrivKey, iv) {
    encPrivKey = hexToBuffer(encPrivKey);
    var privKey = await window.crypto.subtle.decrypt(
        {
        name: "AES-GCM",
        iv: hexToBuffer(iv)
        },
        derivKey,
        encPrivKey
    );
    return crypto.subtle.importKey(
        'pkcs8',
        privKey,
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        false,
        ["decrypt"]
    );
}

function check_password() {
    const enc = new TextEncoder();
    var username = $('#username').val();
    var password = $('#password').val();
    var confirm  = $('#confirm-password').val();
    if(username == '') {
        return error("Username required");
    } else if(password.length < 8) {
        return error("Password must be at least 8 characters long");
    } else if(password != confirm) {
        return error("Passwords do not match");
    }
    generateSecrets(username, password).then(async (res) => {
        var fet = await fetch('/register', {
            method: 'POST',
            headers: {
            'Content-Type': 'application/json;charset=utf-8'
            },
            body: JSON.stringify(res)
        });
        return fet.json();
    }).then((res) => {
        console.log(res);
        if(res.status == "OK") {
            $(location).attr('href', "/");
        } else {
            error(res.error);
        }
    });
}