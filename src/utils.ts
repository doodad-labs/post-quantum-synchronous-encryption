import { createHmac } from 'crypto';

/**
 * Computes an HMAC in a timing-safe manner by padding input data to a fixed length.
 * This mitigates timing attacks that could leak information about the input size.
 * 
 * @param key - HMAC secret key (Buffer)
 * @param data - Input data to hash (Buffer)
 * @returns HMAC-SHA256 digest (Buffer)
 */
function timingSafeHmac(key: Buffer, data: Buffer): Buffer {
    const hmac = createHmac('sha256', key);
    // Pad data to 256 bytes to ensure constant-time processing
    const paddedData = Buffer.concat([data, Buffer.alloc(Math.max(0, 256 - data.length))]);
    hmac.update(paddedData);
    return hmac.digest();
}

/**
 * HKDF (RFC 5869) implementation for secure key derivation.
 * Combines extraction and expansion phases to derive cryptographic keys.
 * 
 * @param ikm - Input Key Material (Buffer)
 * @param salt - Optional salt (Buffer, enhances randomness)
 * @param info - Context/application-specific info (Buffer)
 * @param length - Desired output key length in bytes
 * @returns Derived key (Buffer)
 */
export function hkdf(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
    // --- Extract Phase ---
    // Derives a pseudorandom key (PRK) from IKM and salt
    const prk = timingSafeHmac(salt, ikm);

    // --- Expand Phase ---
    // Calculates how many SHA-256 iterations are needed
    const iterations = Math.ceil(length / 32); // SHA-256 outputs 32-byte chunks
    const buffers: Buffer[] = [];
    let prev = Buffer.alloc(0); // Tracks the previous iteration's output

    for (let i = 0; i < iterations; i++) {
        const hmac = createHmac('sha256', prk);
        // Concatenates prev, info, and iteration counter
        hmac.update(Buffer.concat([prev, info, Buffer.from([i + 1])]));
        prev = hmac.digest();
        buffers.push(prev);
    }

    // Truncates to the exact requested length
    return Buffer.concat(buffers).subarray(0, length);
}

/**
 * Securely zeroes a Buffer to prevent sensitive data from lingering in memory.
 * 
 * @param buffer - Buffer containing sensitive data (e.g., keys)
 */
export function secureZero(buffer: Buffer): void {
    for (let i = 0; i < buffer.length; i++) {
        buffer[i] = 0; // Overwrites each byte with 0
    }
}

/**
 * Pads a string with null bytes (`\0`) to a specified block size.
 * Useful for ensuring fixed-length ciphertexts in encryption schemes.
 * 
 * @param data - Input string
 * @param blockSize - Block size in bytes (default: 1024)
 * @returns Padded string
 */
export function padData(data: string, blockSize = 1024): string {
    const padLength = blockSize - (data.length % blockSize);
    return data + '\0'.repeat(padLength);
}