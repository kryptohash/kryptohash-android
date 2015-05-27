package com.github.kryptohash.kryptohashj.core;

/**
 * Created by Oscar A. Perez on 4/18/2015.
 */

import java.security.NoSuchAlgorithmException;
import com.github.aelstad.keccakj.core.AbstractKeccakMessageDigest;

public class Hasher256 extends AbstractKeccakMessageDigest {
    private final static byte DOMAIN_PADDING = 2;
    private final static int DOMMAIN_PADDING_LENGTH = 2;

    public Hasher256() {
        super("SHA3-256", 2*256, 256/8, DOMAIN_PADDING, DOMMAIN_PADDING_LENGTH);
    }

    /**
     * Calculates the (one-time) double hash of contents and returns it as a new wrapped hash.
     */
    public static byte[] createDoubleHash(byte[] contents) {
        Hasher256 digest1 = new Hasher256();
        digest1.putBytes(contents);
        Hasher256 digest2 = new Hasher256();
        digest2.putBytes(digest1.getHash());
        return digest2.getHash();
    }

    public void putByte(byte _byte) {
        engineUpdate(_byte);
    };

    public void putBytes(byte[] _bytes) {
        engineUpdate(_bytes, 0, _bytes.length);
    };

    public byte[] getHash() {
        return engineDigest();
    };
}
