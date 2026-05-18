// @ts-check

/**
 * @typedef {Object} PasskeyCreationRawResponse
 * @property {string} id - The base64url encoded credential ID.
 * @property {ArrayBuffer} rawId - The raw credential ID.
 * @property {Object} response - The authenticator response.
 * @property {ArrayBuffer} response.attestationObject - The raw attestation object.
 * @property {ArrayBuffer} response.clientDataJSON - The raw client data JSON.
 * @property {string[]} response.transports - The available transports (e.g., 'internal', 'usb').
 * @property {string} type - The credential type (usually 'public-key').
 * @property {AuthenticationExtensionsClientOutputs} clientExtensionResults - Results of any requested extensions (like PRF).
 */

/**
 * @typedef {Object} PasskeyAssertionRawResponse
 * @property {string} id - The base64url encoded credential ID.
 * @property {ArrayBuffer} rawId - The raw credential ID.
 * @property {Object} response - The authenticator response.
 * @property {ArrayBuffer} response.authenticatorData - The raw authenticator data.
 * @property {ArrayBuffer} response.clientDataJSON - The raw client data JSON.
 * @property {ArrayBuffer} response.signature - The raw signature.
 * @property {ArrayBuffer | null} response.userHandle - The raw user handle.
 * @property {string} type - The credential type (usually 'public-key').
 * @property {AuthenticationExtensionsClientOutputs} clientExtensionResults - Results of any requested extensions.
 */

/**
 * @typedef {Object} StoredPasskeyJSON
 * @property {string} id - The base64url encoded credential ID.
 * @property {Object} response - The authenticator response.
 * @property {AuthenticatorTransport[]} [response.transports] - The available transports.
 */

/**
 * Checks if the browser supports Passkeys (WebAuthn) and the PRF extension.
 *
 * @returns {Promise<boolean>}
 */
export async function checkPasskeySupport() {
    if (!window.PublicKeyCredential) {
        return false;
    }

    // Check for platform authenticator availability
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    return available;
}

/**
 * Creates a new Passkey (Discoverable Credential) using raw buffers.
 *
 * @param {Uint8Array} challenge - The challenge from the server.
 * @param {{id: Uint8Array, name: string, displayName: string}} user - The user information.
 * @param {AuthenticatorAttachment} attachment - The authenticator attachment (platform or cross-platform).
 * @param {string} rpName - The Relying Party name.
 * @returns {Promise<PasskeyCreationRawResponse>} - The credential data to be sent to the server.
 */
export async function createPasskeyRaw(challenge, user, attachment = "platform", rpName = "Wallet App") {

    /** @type {PublicKeyCredentialCreationOptions} */
    const publicKeyCredentialCreationOptions = {
        challenge: /** @type {any} */ (challenge),
        rp: {
            name: rpName,
            id: window.location.hostname,
        },
        user: {
            id: /** @type {any} */ (user.id),
            name: user.name,
            displayName: user.displayName,
        },
        pubKeyCredParams: [
            { alg: -7, type: "public-key" }, // ES256
            { alg: -257, type: "public-key" }, // RS256
        ],
        authenticatorSelection: {
            authenticatorAttachment: attachment,
            userVerification: "required",
            residentKey: "required",
            requireResidentKey: true,
        },
        extensions: {
            // Request PRF extension support
            // @ts-ignore
            prf: {}
        },
        timeout: 60000,
        attestation: "none",
    };

    const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions,
    });

    if (!credential || !(credential instanceof PublicKeyCredential)) {
        throw new Error("Credential creation failed");
    }

    const clientExtensionResults = credential.getClientExtensionResults();

    if (!clientExtensionResults.prf || !clientExtensionResults.prf.enabled) {
        throw new Error("PRF extension not supported");
    }

    const toServer = credential.toJSON();
    localStorage.setItem("thepasskey", JSON.stringify(toServer));
    console.log(toServer);

    const response = /** @type {AuthenticatorAttestationResponse} */ (credential.response);

    // Prepare object for server
    return {
        id: credential.id,
        rawId: credential.rawId,
        response: {
            attestationObject: response.attestationObject,
            clientDataJSON: response.clientDataJSON,
            transports: response.getTransports ? response.getTransports() : [],
        },
        type: credential.type,
        clientExtensionResults: clientExtensionResults,
    };
}

/**
 * Authenticates the user using a Passkey (Assertion).
 * Generates a local challenge and performs basic client-side verifications.
 *
 * @returns {Promise<PasskeyAssertionRawResponse>} - The assertion data.
 */
export async function getPasskeyRaw() {
    // Generate a local challenge (32 random bytes) as there is no server
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));

    const storedPasskeyString = localStorage.getItem("thepasskey");
    if (!storedPasskeyString) {
        throw new Error("No passkey found in storage. Please create one first.");
    }
    /** @type {StoredPasskeyJSON} */
    const storedPasskey = JSON.parse(storedPasskeyString);

    /** @type {PublicKeyCredentialRequestOptions} */
    const publicKeyCredentialRequestOptions = {
        challenge: /** @type {any} */ (challenge),
        rpId: window.location.hostname,
        allowCredentials: [
            {
                id: base64UrlToBuffer(storedPasskey.id),
                type: "public-key",
                transports: storedPasskey.response.transports || [],
            }
        ],
        userVerification: "required",
        extensions: {
            // Request PRF extension support if needed for local encryption keys
            // @ts-ignore
            prf: {}
        },
        timeout: 60000,
    };

    const credential = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
    });

    if (!credential || !(credential instanceof PublicKeyCredential)) {
        throw new Error("Authentication failed");
    }

    const response = /** @type {AuthenticatorAssertionResponse} */ (credential.response);


    // --- Basic Verifications (Local "Server-side" checks) ---

    // 1. Verify clientDataJSON
    const clientDataJSON = JSON.parse(new TextDecoder().decode(response.clientDataJSON));

    if (clientDataJSON.type !== "webauthn.get") {
        throw new Error("Invalid credential type");
    }

    if (clientDataJSON.origin !== window.location.origin) {
        throw new Error("Origin mismatch");
    }

    const receivedChallenge = base64UrlToBuffer(clientDataJSON.challenge);
    if (!buffersEqual(receivedChallenge, challenge)) {
        throw new Error("Challenge mismatch");
    }

    // 2. Verify authenticatorData
    const authData = new Uint8Array(response.authenticatorData);

    // Verify RP ID Hash (first 32 bytes of authData)
    const rpIdHash = authData.slice(0, 32);
    const expectedRpIdHash = new Uint8Array(await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(window.location.hostname)));
    if (!buffersEqual(rpIdHash, expectedRpIdHash)) {
        throw new Error("RP ID hash mismatch");
    }

    // Verify Flags (byte 32)
    const flags = authData[32];
    const UP = !!(flags & 0x01); // User Present bit
    const UV = !!(flags & 0x04); // User Verified bit

    if (!UP) throw new Error("User not present");
    if (!UV) throw new Error("User not verified");

    return {
        id: credential.id,
        rawId: credential.rawId,
        response: {
            authenticatorData: response.authenticatorData,
            clientDataJSON: response.clientDataJSON,
            signature: response.signature,
            userHandle: response.userHandle,
        },
        type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),
    };
}

/**
 * Derives a keypair (deterministic secret) from the passkey using the PRF extension.
 * 
 * @param {Uint8Array} salt - A 32-byte salt to derive the key from.
 * @returns {Promise<{ privateKey: Uint8Array, credentialId: string }>} - The derived private key (PRF output) and credential ID.
 */
export async function deriveKeyFromPasskey(salt) {
    if (!salt || salt.length < 32) {
        throw new Error("Salt must be at least 32 bytes.");
    }

    const storedPasskeyString = localStorage.getItem("thepasskey");
    if (!storedPasskeyString) {
        throw new Error("No passkey found in storage. Please create one first.");
    }
    /** @type {StoredPasskeyJSON} */
    const storedPasskey = JSON.parse(storedPasskeyString);

    /** @type {PublicKeyCredentialRequestOptions} */
    const publicKeyCredentialRequestOptions = {
        challenge: window.crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        allowCredentials: [
            {
                id: base64UrlToBuffer(storedPasskey.id),
                type: "public-key",
                transports: storedPasskey.response.transports || [],
            }
        ],
        userVerification: "required",
        extensions: {
            prf: {
                eval: {
                    first: /** @type {any} */ (salt)
                }
            }
        },
        timeout: 60000,
    };

    const credential = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
    });

    if (!credential || !(credential instanceof PublicKeyCredential)) {
        throw new Error("Authentication failed");
    }

    const clientExtensionResults = credential.getClientExtensionResults();

    // @ts-ignore
    if (!clientExtensionResults.prf || !clientExtensionResults.prf.results || !clientExtensionResults.prf.results.first) {
        throw new Error("PRF extension failed or not supported by the authenticator.");
    }

    // @ts-ignore
    const prfOutput = new Uint8Array(clientExtensionResults.prf.results.first);

    return {
        privateKey: prfOutput,
        credentialId: credential.id
    };
}

// /**
//  * Derives an ES256 (ECDSA P-256) keypair from the passkey using the PRF extension.
//  * 
//  * @param {string} saltString - A string to generate the salt from (e.g. "signing", "encryption").
//  * @returns {Promise<{ keyPair: CryptoKey, credentialId: string }>} - The derived CryptoKey (private) and credential ID.
//  */
// export async function deriveEC(saltString) {
//     // 1. Create a 32-byte salt from the input string
//     const encoder = new TextEncoder();
//     const data = encoder.encode(saltString);
//     const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
//     const salt = new Uint8Array(hashBuffer);

//     // 2. Derive the 32-byte deterministic secret (private key scalar)
//     const { privateKey: privateKeyBytes, credentialId } = await deriveKeyFromPasskey(salt);

//     // 3. Compute the Public Key from the Private Key using 'elliptic' library
//     //    We need this because Web Crypto can't import a raw private scalar directly.
//     const EC = elliptic.ec;
//     const ec = new EC('p256');

//     // Generate key pair from private key
//     const key = ec.keyFromPrivate(privateKeyBytes);

//     // Get public key components (x, y)
//     const pubPoint = key.getPublic();

//     // 4. Construct a JWK (JSON Web Key)
//     // We convert the BN (BigNum) coordinates to Base64Url strings
//     /** @type {JsonWebKey} */
//     const jwk = {
//         kty: "EC",
//         crv: "P-256",
//         x: toBase64Url(new Uint8Array(pubPoint.getX().toArray('be', 32))),
//         y: toBase64Url(new Uint8Array(pubPoint.getY().toArray('be', 32))),
//         d: toBase64Url(privateKeyBytes), // The private key scalar
//         ext: true,
//         key_ops: ["sign"],
//         alg: "ES256"
//     };

//     // 5. Import into Web Crypto as a native CryptoKey
//     const cryptoKey = await window.crypto.subtle.importKey(
//         "jwk",
//         jwk,
//         {
//             name: "ECDSA",
//             namedCurve: "P-256"
//         },
//         true, // extractable
//         ["sign"]
//     );

//     return {
//         keyPair: cryptoKey,
//         credentialId: credentialId
//     };
// }

/**
 * Helper to convert Uint8Array to Base64Url string (needed for JWK)
 * @param {Uint8Array} buffer 
 */
function toBase64Url(buffer) {
    const binString = Array.from(buffer, (byte) => String.fromCodePoint(byte)).join("");
    return btoa(binString)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}



// Helper functions

/**
 * @param {string | any[]} base64url
 */
function base64UrlToBuffer(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

/**
 * @param {any} buffer
 */
function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Compares two Uint8Array buffers for equality.
 * 
 * @param {Uint8Array} a 
 * @param {Uint8Array} b 
 * @returns {boolean}
 */
function buffersEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}