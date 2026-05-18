// @ts-check

/**
 * Generates a P-256 key pair, extracts the private and public keys in hexadecimal format,
 * and generates a DID key from the public key.
 *
 * This function orchestrates the process of creating cryptographic keys and a DID.
 * It calls other functions to generate the key pair, extract the private and public keys,
 * and then generate the DID key.
 *
 * @async
 * @function generateP256
 * @returns {Promise<{did: string, privateKey: JsonWebKey, publicKey: JsonWebKey}>} - A promise that resolves when the key generation and DID creation are complete.
 */
export async function generateP256did() {
    const nativeKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        true,
        ["sign", "verify"]
    );

    let privateKeyJWK = await crypto.subtle.exportKey("jwk", nativeKeyPair.privateKey);

    let publicKeyJWK = await crypto.subtle.exportKey("jwk", nativeKeyPair.publicKey);

    const privateKeyHex = await generateP256PrivateKeyHex(nativeKeyPair);

    const publicKeyHex = await generateP256PublicKeyHex(nativeKeyPair);

    const did = await generateDidKey(publicKeyHex);
    return { did: did, privateKey: privateKeyJWK, publicKey: publicKeyJWK };
}

/**
 * Extracts the private key from a P-256 key pair and returns it in PKCS#8 hexadecimal format.
 *
 * @async
 * @function generateP256PrivateKeyHex
 * @param {CryptoKeyPair} keyPair - The key pair containing the private key.
 * @returns {Promise<string>} - A promise that resolves with the private key in hexadecimal format.
 */
async function generateP256PrivateKeyHex(keyPair) {
    const privateKeyPkcs8 = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    const privateKeyPkcs8Bytes = new Uint8Array(privateKeyPkcs8);

    const privateKeyPkcs8Hex = bytesToHexString(privateKeyPkcs8Bytes);
    console.log("Private Key P-256 (Secp256r1) PKCS#8 (HEX): ", privateKeyPkcs8Hex);

    const privateKeyBytes = privateKeyPkcs8Bytes.slice(36, 36 + 32);

    const privateKeyHexBytes = bytesToHexString(privateKeyBytes);

    return privateKeyHexBytes;
}

/**
 * Extracts the public key from a P-256 key pair and returns it in raw hexadecimal format.
 *
 * @async
 * @function generateP256PublicKeyHex
 * @param {CryptoKeyPair} keyPair - The key pair containing the public key.
 * @returns {Promise<string>} - A promise that resolves with the public key in hexadecimal format.
 */
async function generateP256PublicKeyHex(keyPair) {
    const publicKey = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);

    const publicKeyBytes = new Uint8Array(publicKey);

    return bytesToHexString(publicKeyBytes);
}

/**
 * Generates a DID key from a P-256 public key in hexadecimal format.
 *
 * @async
 * @function generateDidKey
 * @param {string} publicKeyHex - The public key in hexadecimal format.
 * @returns {Promise<string>} - A promise that resolves with the generated DID key.
 */
async function generateDidKey(publicKeyHex) {
    const publicKeyHexWithout0xAndPrefix = publicKeyHex.slice(4);

    const publicKeyX = publicKeyHexWithout0xAndPrefix.slice(0, 64);

    const publicKeyY = publicKeyHexWithout0xAndPrefix.slice(64);
    const isPublicKeyYEven = isHexNumberEven(publicKeyY);

    const compressedPublicKeyX = (isPublicKeyYEven ? "02" : "03") + publicKeyX;

    // The number 8024 is the hex varint representation of 0x1200 (multicodec P-256 public Key compressed)
    const multicodecHex = "8024" + compressedPublicKeyX;

    const multicodecBytes = multicodecHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16));
    var b58MAP = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const multicodecBase58 = base58encode(multicodecBytes, b58MAP);

    return "did:key:z" + multicodecBase58;
}

/**
 * Converts an array of bytes to a hexadecimal string, prefixed with "0x".
 *
 * @function bytesToHexString
 * @param {Uint8Array} bytesToTransform - The array of bytes to convert.
 * @returns {string} - The hexadecimal string representation of the bytes.
 */
function bytesToHexString(bytesToTransform) {
    return `0x${Array.from(bytesToTransform)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")}`;
}

/**
 * Checks if a hexadecimal number is even.
 *
 * @function isHexNumberEven
 * @param {string} hexNumber - The hexadecimal number to check.
 * @returns {boolean} - True if the number is even, false otherwise.
 */
function isHexNumberEven(hexNumber) {
    const decimalNumber = BigInt("0x" + hexNumber);
    const stringNumber = decimalNumber.toString();

    const lastNumPosition = stringNumber.length - 1;
    const lastNumDecimal = parseInt(stringNumber[lastNumPosition]);

    const isEven = lastNumDecimal % 2 === 0;
    return isEven;
}

/**
 * Encodes a byte array into a Base58 string.
 *
 * @function base58encode
 * @param {number[]} B - The Uint8Array of raw bytes to encode.
 * @param {string} A - The Base58 character set.
 * @returns {string} - The Base58 encoded string.
 */
function base58encode(
    B, //Uint8Array raw byte input
    A //Base58 characters (i.e. "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
) {
    var d = [], //the array for storing the stream of base58 digits
        s = "", //the result string variable that will be returned
        i, //the iterator variable for the byte input
        j, //the iterator variable for the base58 digit array (d)
        c, //the carry amount variable that is used to overflow from the current base58 digit to the next base58 digit
        n; //a temporary placeholder variable for the current base58 digit
    for (i in B) {
        //loop through each byte in the input stream
        (j = 0), //reset the base58 digit iterator
            (c = B[i]); //set the initial carry amount equal to the current byte amount
        // @ts-ignore
        s += c || s.length ^ i ? "" : 1; //prepend the result string with a "1" (0 in base58) if the byte stream is zero and non-zero bytes haven't been seen yet (to ensure correct decode length)
        while (j in d || c) {
            //start looping through the digits until there are no more digits and no carry amount
            n = d[j]; //set the placeholder for the current base58 digit
            n = n ? n * 256 + c : c; //shift the current base58 one byte and add the carry amount (or just add the carry amount if this is a new digit)
            c = (n / 58) | 0; //find the new carry amount (floored integer of current digit divided by 58)
            d[j] = n % 58; //reset the current base58 digit to the remainder (the carry amount will pass on the overflow)
            j++; //iterate to the next base58 digit
        }
    }
    while (j--)
        //since the base58 digits are backwards, loop through them in reverse order
        s += A[d[j]]; //lookup the character associated with each base58 digit
    return s; //return the final base58 string
}

/**
 * Calculates the SHA-256 hash of a message.
 *
 * @async
 * @function sha256
 * @param {string} message - The message to hash.
 * @returns {Promise<string>} - A promise that resolves with the SHA-256 hash in hexadecimal format.
 */
async function sha256(message) {
    // encode as UTF-8
    const msgBuffer = new TextEncoder().encode(message);

    // hash the message
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);

    // convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // convert bytes to hex string
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    return hashHex;
}
