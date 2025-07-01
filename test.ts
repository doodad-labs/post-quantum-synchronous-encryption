import { VERSION, encrypt, decrypt, generateKeys, exportKeys, importKeys } from "./dist/index";
import { randomBytes } from "crypto";

async function test() {

    console.log(`  __QQ    \x1b[1mhsynchronous ${VERSION}\x1b[0m`);
    console.log(` (_)_\x1b[31m"\x1b[0m>   Post-Quantum Synchronous Encryption`);
    console.log(`_)        \x1b[2mgithub.com/doodad-labs\x1b[0m`);

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

    const perf_encrypt_raw = performance.now();
    await encrypt(original, keypair, {
        fixedRunTime: false,
    }, nonce);
    const perf_encrypt_end_raw = performance.now();

    const perf_decrypt_raw = performance.now();
    await decrypt(encrypted, keypair, {
        fixedRunTime: false,
        memoryNonceProtection: false, // Disable nonce protection for raw timing
    });
    const perf_decrypt_end_raw = performance.now();

    const key = await exportKeys(keypair);
    const importedKeypair = await importKeys(key);
    const importedEncrypted = await encrypt(original, importedKeypair);
    const importedDecrypted = await decrypt(importedEncrypted, importedKeypair);

    console.log("\n\x1b[1mfunctionality -----------\x1b[0m");
    console.log("Decrypted Correctly:\t", original === decrypted.message ? "\x1b[42m Yes" : "\x1b[41m No", "\x1b[0m");
    console.log("Correct Nonce:\t\t", decrypted.nonce === nonce ? "\x1b[42m Yes" : "\x1b[41m No", "\x1b[0m");
    console.log("Working Encryption:\t", decrypted.nonce === nonce && original === decrypted.message ? "\x1b[42m Yes" : "\x1b[41m No", "\x1b[0m");
    console.log("Key import Working:\t", original === importedDecrypted.message ? "\x1b[42m Yes" : "\x1b[41m No", "\x1b[0m");

    console.log("\n\x1b[1mmetadata ----------------\x1b[0m");
    console.log("Encrypted At:\t\t", decrypted.createdAt);
    console.log("Decrypted At:\t\t", decrypted.decryptedAt);

    console.log("\n\x1b[1msizes -------------------\x1b[0m");
    console.log("Original Length:\t", original.length);
    console.log("Encrypted Length:\t", encrypted.length, `+${encrypted.length - original.length} bytes`, `+${((encrypted.length - original.length) / original.length * 100).toFixed(2)}%`);
    console.log('Exported key Length:\t', key.length, 'bytes');

    console.log("\n\x1b[1mtimings -----------------\x1b[0m");
    console.log("Encryption Time (ms):\t", perf_encrypt_end - perf_encrypt, "(Timing-Safe)");
    console.log("Decryption Time (ms):\t", perf_decrypt_end - perf_decrypt, "(Timing-Safe)");
    console.log("Encryption Time (ms):\t", perf_encrypt_end_raw - perf_encrypt_raw, "(Raw)");
    console.log("Decryption Time (ms):\t", perf_decrypt_end_raw - perf_decrypt_raw, "(Raw)");

    if (decrypted.nonce === nonce && original === decrypted.message && original === importedDecrypted.message) {
        process.exit(0);
    } else {
        console.error("Test failed, exiting with error code 1");
        process.exit(1);
    }
}

test().catch(console.error)