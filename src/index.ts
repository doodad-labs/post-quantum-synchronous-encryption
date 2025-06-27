import { encrypt, decrypt, generateKeys } from "./synchronous";
import { randomBytes } from "crypto";

async function example() {
    const keypair = await generateKeys();
    const original = randomBytes(1000).toString('hex'); // Random 32-byte string

    const perf_encrypt = performance.now();
    const encrypted = await encrypt(original, keypair);
    const perf_encrypt_end = performance.now();

    const perf_decrypt = performance.now();
    const decrypted = await decrypt(encrypted, keypair);
    const perf_decrypt_end = performance.now();

    console.log("Original Length:", original.length);
    console.log("Decrypted Length:", decrypted.length);
    console.log("Working:", original === decrypted ? "Yes" : "No");

    console.log("\nEncrypted Length:", encrypted.length, `+${encrypted.length - original.length} bytes`, `+${((encrypted.length - original.length) / original.length * 100).toFixed(2)}%`);

    console.log("\nEncryption Time (ms):", perf_encrypt_end - perf_encrypt);
    console.log("Decryption Time (ms):", perf_decrypt_end - perf_decrypt);
}

example().catch(console.error)