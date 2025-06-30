import { encrypt, decrypt, generateKeys } from "./src";
import { randomBytes } from "crypto";
import { run, bench } from 'mitata';

async function example() {
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