import { encrypt, decrypt, generateKeys } from "./synchronous";
import { randomBytes } from "crypto";

async function example() {
    const keypair = await generateKeys();
    const original = randomBytes(125).toString('hex'); // Random 32-byte string

    const perf_encrypt = performance.now();
    const encrypted = await encrypt(original, keypair);
    const perf_encrypt_end = performance.now();

    const perf_decrypt = performance.now();
    const decrypted = await decrypt(encrypted, keypair);
    const perf_decrypt_end = performance.now();

    console.log("Original:", original);
    console.log("Decrypted:", decrypted);
    console.log("Working:", original === decrypted ? "Yes" : "No");

    console.log("\nEncrypted Length:", encrypted.length);

    console.log("\nEncryption Time (ms):", perf_encrypt_end - perf_encrypt);
    console.log("Decryption Time (ms):", perf_decrypt_end - perf_decrypt);
}

example().catch(console.error)