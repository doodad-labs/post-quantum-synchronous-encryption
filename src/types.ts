import type { kem, sign } from 'pqclean';

export interface generateKeysFunc {
    (
        KEM_ALGORITHM?: string,
        SIG_ALGORITHM?: string
    ): Promise<{
        kemKeyPair: kem.GenerateKeyPairResult,
        sigKeyPair: sign.GenerateKeyPairResult
    }>;
}

export interface encryptFunc {
    (
        message: string,
        keypair: {
            kemKeyPair: kem.GenerateKeyPairResult,
            sigKeyPair: sign.GenerateKeyPairResult
        },
        options?: {
            fixedRunTime?: boolean // If true, will always take at least MIN_PROCESSING_TIME
        },
        nonce?: string
    ): Promise<string>;
}

export interface decryptFunc {
    (
        payload: string,
        keypair: {
            kemKeyPair: kem.GenerateKeyPairResult,
            sigKeyPair: sign.GenerateKeyPairResult
        },
        options?: {
            fixedRunTime?: boolean // If true, will always take at least MIN_PROCESSING_TIME
            memoryNonceProtection?: boolean // If true, will check in-memory nonce history to prevent reuse
        }
    ): Promise<{
        message: string,
        createdAt: Date,
        decryptedAt: Date,
        nonce: string
    }>;
}

export interface exportKeysFunc {
    (
        keypair: {
            kemKeyPair: kem.GenerateKeyPairResult,
            sigKeyPair: sign.GenerateKeyPairResult
        },
    ): Promise<string>;
}

export interface importKeysFunc {
    (
        keys: string,
    ): Promise<{
        kemKeyPair: kem.GenerateKeyPairResult,
        sigKeyPair: sign.GenerateKeyPairResult
    }>;
}