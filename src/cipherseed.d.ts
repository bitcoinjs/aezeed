/// <reference types="node" />
export declare class CipherSeed {
    internalVersion: number;
    entropy: Buffer;
    birthday: number;
    private salt;
    private static decipher;
    static fromMnemonic(mnemonic: string, password?: string): CipherSeed;
    constructor(internalVersion?: number, entropy?: Buffer, now?: Date);
    private encipher;
    toMnemonic(password?: string, cipherSeedVersion?: number): string;
}
