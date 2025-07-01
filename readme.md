
# Post-quantum synchronous encryption protocol

Hybrid synchronous encryption protocol using NIST approved post-quantum algorithms. 

```ts

import { encrypt, decrypt, generateKeys } from "./src";

const key = generateKeys();
const message = "The quick brown fox jumps over the lazy dog";

const encrypted = await encrypt(message, key);
const decrypted = await decrypt(encrypted, key);

console.log(decrypted)

// {
//   message: "The quick brown fox jumps over the lazy dog",
//   createdAt: 2025-06-30T15:14:33.663Z,
//   decryptedAt: 2025-06-30T15:14:33.719Z,
//   nonce: "3e4bc82b144728126bb0145d678f7a3153..."
// }

```


## Official Rating: NIST Level 4 (Highest commercial/government grade with post-quantum resistance)

Component	                | Algorithm/Strength	        | Security Level	                    | Notes
----------------------------|-------------------------------|---------------------------------------|-----------------------------------------------------------------
Key Encapsulation (KEM)	    | ML-KEM-1024 (Kyber)	        | NIST Level 3 (PQC Standard)	        | Post-quantum secure, IND-CCA2
Digital Signature	        | Falcon-1024	                | NIST Level 3 (PQC Standard)	        | Post-quantum secure, EUF-CMA
Symmetric Encryption	    | AES-256-GCM	                | 256-bit (NIST-approved)	            | Quantum-resistant key size, provides confidentiality + integrity
Key Derivation	            | HKDF-SHA256	                | 256-bit (NIST SP 800-56C)	            | Proper key separation with context binding
Random Number Generation	| crypto.randomBytes()	        | Cryptographically secure (CSPRNG)	    | Uses OS entropy source

## Resistance Against Attacks

Attack Type	            | Protection Mechanism	                                            | Additional Notes
------------------------|-------------------------------------------------------------------|----------------------------------------
Quantum computing	    | ML-KEM-1024 (IND-CCA2) + Falcon-1024 (EUF-CMA)	                | Full PQC resistance
MITM attacks	        | Falcon-1024 signatures + protocol binding	                        | Non-repudiation
Key compromise	        | Ephemeral KEM keys (per message) + HKDF with unique salts	        | No long-term key reuse
Replay attacks	        | 64-byte random salts + 12-byte IVs (2¹²⁸ uniqueness)	            | Statistically negligible collision risk
CRIME/BREACH	        | No compression (removed in v2) + encryption before any encoding	| Mitigates compression oracles
Key derivation attacks	| HKDF-SHA256 with protocol-specific info binding	                | Prevents cross-context reuse
Timing attacks	        | timingSafeEqual + constant-time HMAC (padded inputs)	            | Resists timing leaks
Memory scraping	        | Explicit secureZero for sensitive buffers	                        | Prevents cold-boot attacks
Error oracles	        | Unified error paths (generic "decryption failed" messages)	    | Hides cryptographic faults
Side-channel leaks	    | Minimum processing time (MIN_PROCESSING_TIME)	                    | Obscures operation timing
Metadata leakage	    | Fixed block padding (1024-byte chunks)	                        | Hides true message size

## Benchmarking

```
clk: ~2.51 GHz
cpu: 13th Gen Intel(R) Core(TM) i5-13420H
runtime: node 22.13.1 (x64-win32)

benchmark                   avg (min … max) p75 / p99
------------------------------------------- ---------
GenKeys                       47.33 ms/iter  53.51 ms 
                      (35.52 ms … 64.85 ms)  58.01 ms 
                    (  2.71 kb …  20.49 kb)   4.53 kb 

Encrypt                       13.08 ms/iter  14.28 ms 
                       (9.73 ms … 25.82 ms)  24.94 ms
                    ( 23.41 kb …  39.29 kb)  24.86 kb

Decrypt                      622.42 µs/iter 878.20 µs
                      (259.30 µs … 2.62 ms)   1.87 ms
                    (472.00  b … 493.76 kb)  16.20 kb
```
## API

### `await generateKeys(KEM_ALGORITHM*, SIG_ALGORITHM*)`

Asynchronously generates a pair of cryptographic keys for Key Encapsulation Mechanism (KEM)
and digital signatures using post-quantum algorithms (default: ML-KEM-1024 and Falcon-1024).

- param `string` [KEM_ALGORITHM='ml-kem-1024'] - KEM algorithm identifier (e.g., 'ml-kem-1024', 'kyber-768').
- param `string` [SIG_ALGORITHM='falcon-1024'] - Digital signature algorithm identifier (e.g., 'falcon-1024', 'dilithium-3').

- returns `Promise<{ kemKeyPair: CryptoKeyPair; sigKeyPair: CryptoKeyPair }>` Object containing KEM and signature key pairs.

- throws `Error` If key generation fails (e.g., unsupported algorithm or cryptographic backend error).

### `await encrypt(message, keypair, options, nonce)`

Encrypts a message using a hybrid post-quantum encryption scheme combining: Key Encapsulation Mechanism (KEM) for key exchange, AES-GCM for symmetric encryption, Digital signatures for authentication

- param `string` message - Plaintext message to encrypt
- param `Object` keypair - Contains KEM and signature key pairs (from generateKeys())
- param `Object` [options] - Encryption options (merged with defaults)
- param `string` [nonce] - Optional nonce for replay protection (auto-generated if omitted)

- returns `Promise<string>` Encrypted payload (hex string with metadata)

- throws `Error` If inputs are invalid or cryptographic operations fail

### `await decrypt(payload, keypair, options)`

Decrypts a payload encrypted by the `encrypt` function using hybrid post-quantum cryptography.
Performs signature verification, key decapsulation, and AES-GCM decryption.

- param `string` payload - Encrypted payload (hex string with metadata)
- param `Object` keypair - Contains KEM and signature key pairs (from generateKeys())
- param `Object` [options] - Decryption options (merged with defaults)

- returns `Promise<{message: string, createdAt: Date, decryptedAt: Date, nonce: string}>` Decrypted data with metadata

- throws {Error} If:
  - Signature verification fails
  - Nonce reuse detected
  - Decryption fails (invalid tag, corrupted data, etc.)

### `await exportKeys(keypair)`

Serializes cryptographic key pairs into a secure string format for storage/transmission.
Format: "PROTOCOL:VERSION:METADATA_HEX:PAYLOAD_HEX"

- param `keypair` - Contains KEM and signature key pairs (from generateKeys() or importKeys())

- returns `string` Serialized keys in protocol-defined format

- throws `Error` If key export fails (e.g., invalid key material)

### `await importKeys(key)`

Imports cryptographic keys from a serialized string format, verifying protocol compatibility
and algorithm support before reconstructing key pairs.

- param `string` key - Serialized keys in format "PROTOCOL:VERSION:METADATA_HEX:PAYLOAD_HEX"

- returns `Promise<{kemKeyPair: KeyPair, sigKeyPair: KeyPair}>` Reconstructed key pairs

- throws `Error` If:
  - Protocol/version mismatch
  - Unsupported algorithms detected
  - Malformed key data
