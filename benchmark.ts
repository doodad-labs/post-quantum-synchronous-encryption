import { encrypt, decrypt, generateKeys } from "./src";
import { randomBytes } from "crypto";
import { run, bench } from 'mitata';

async function example() {
    const keypair = await generateKeys();
    const nonce = randomBytes(64).toString('hex'); // Random 16-byte nonce
    const original = randomBytes(1000).toString('hex'); // Random 32-byte string

    const perf_encrypt = performance.now();
    const encrypted = await encrypt(original, keypair, {
        fixedRunTime: true,
    }, nonce);
    const perf_encrypt_end = performance.now();

    const perf_decrypt = performance.now();
    const decrypted = await decrypt(encrypted, keypair);
    const perf_decrypt_end = performance.now();

    console.log("\nCorrect Message:\t", original === decrypted.message ? "Yes" : "No");
    console.log("Correct Nonce:\t\t", decrypted.nonce === nonce ? "Yes" : "No");
    console.log("Working Encryption:\t", decrypted.nonce === nonce && original === decrypted.message ? "Yes" : "No");

    console.log("\nEncrypted At:\t", decrypted.createdAt);
    console.log("Decrypted At:\t", decrypted.decryptedAt);

    console.log("\nOriginal Length:\t", original.length);
    console.log("Encrypted Length:\t", encrypted.length, `+${encrypted.length - original.length} bytes`, `+${((encrypted.length - original.length) / original.length * 100).toFixed(2)}%`);

    console.log("\nEncryption Time (ms):\t", perf_encrypt_end - perf_encrypt);
    console.log("Decryption Time (ms):\t", perf_decrypt_end - perf_decrypt);

    if (decrypted.nonce !== nonce && original !== decrypted.message) return;

    console.log('\nStarting benchmarks...\n');

    let benchKeypair = await generateKeys();
    let benchNonce = randomBytes(64).toString('hex'); // Random 16-byte nonce
    let benchOriginal = randomBytes(1000).toString('hex'); // Random 32-byte string
    let benchOptionsEncrypt = {
        fixedRunTime: false,
    }
    let benchOptionsDecrypt = {
        fixedRunTime: false,
        memoryNonceProtection: false,
    }
    let benchEncrypted = await encrypt(benchOriginal, benchKeypair, benchOptionsEncrypt, benchNonce);

    bench('GenKeys', () => 
        generateKeys()
    )

    bench('Encrypt', () => 
        encrypt(benchOriginal, benchKeypair, benchOptionsEncrypt, benchNonce)
    );

    bench('Decrypt', () => 
        decrypt(benchEncrypted, benchKeypair, benchOptionsDecrypt)
    )

    await run();
}

example().catch(console.error)