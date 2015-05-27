/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.kryptohash.kryptohashj.crypto;

import com.github.kryptohash.kryptohashj.core.Ed25519Key;
import com.github.kryptohash.kryptohashj.core.Transaction;
import com.github.kryptohash.kryptohashj.core.VerificationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * A TransactionSignature wraps an {@link com.github.kryptohash.kryptohashj.core.Ed25519Key.stdEd25519Sig} and adds methods for handling
 * the additional SIGHASH mode byte that is used.
 */
public class TxEd25519Signature extends Ed25519Key.stdEd25519Sig {
    /**
     * A byte that controls which parts of a transaction are signed. This is exposed because signatures
     * parsed off the wire may have sighash flags that aren't "normal" serializations of the enum values.
     * Because Satoshi's code works via bit testing, we must not lose the exact value when round-tripping
     * otherwise we'll fail to verify signature hashes.
     */
    public final int sighashFlags;

    /** Constructs a signature with the given components and SIGHASH_ALL. */
    public TxEd25519Signature(BigInteger sig) {
        this(sig, Transaction.SigHash.ALL.ordinal() + 1);
    }

    /** Constructs a signature with the given components and raw sighash flag bytes (needed for rule compatibility). */
    public TxEd25519Signature(BigInteger sig, int sighashFlags) {
        super(sig);
        this.sighashFlags = sighashFlags;
    }

    /** Constructs a transaction signature based on the Ed25519 signature. */
    public TxEd25519Signature(Ed25519Key.stdEd25519Sig signature, Transaction.SigHash mode, boolean anyoneCanPay) {
        super(signature.sig);
        sighashFlags = calcSigHashValue(mode, anyoneCanPay);
    }

    /**
     * Returns a dummy invalid signature that they will take up the same number of encoded bytes as a real signature.
     * This can be useful when you want to fill out a transaction to be of the right size (e.g. for fee calculations)
     * but don't have the requisite signing key yet and will fill out the real signature later.
     */
    public static TxEd25519Signature dummy() {
        Ed25519Key.stdEd25519Sig sig = new Ed25519Key.stdEd25519Sig();
        return new TxEd25519Signature(sig.getBigInteger());
    }

    /** Calculates the byte used in the protocol to represent the combination of mode and anyoneCanPay. */
    public static int calcSigHashValue(Transaction.SigHash mode, boolean anyoneCanPay) {
        int sighashFlags = mode.ordinal() + 1;
        if (anyoneCanPay)
            sighashFlags |= Transaction.SIGHASH_ANYONECANPAY_VALUE;
        return sighashFlags;
    }

    public boolean anyoneCanPay() {
        return (sighashFlags & Transaction.SIGHASH_ANYONECANPAY_VALUE) != 0;
    }

    public Transaction.SigHash sigHashMode() {
        final int mode = sighashFlags & 0x1f;
        if (mode == Transaction.SigHash.NONE.ordinal() + 1)
            return Transaction.SigHash.NONE;
        else if (mode == Transaction.SigHash.SINGLE.ordinal() + 1)
            return Transaction.SigHash.SINGLE;
        else
            return Transaction.SigHash.ALL;
    }

    /**
     * What we get back from the signer is a signature. To get a flat byte stream of the type used
     * by Kryptohash we have to encode them using Kryptohash standard encoding, which is just a way
     * to pack the signature and private key into a structure, and then we append a byte to the end
     * for the sighash flags.
     */
    public byte[] encodeToKryptohash() {
        try {
            ByteArrayOutputStream bos = byteStream();
            bos.write(sighashFlags);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Returns a decoded signature.
     * @throws RuntimeException if the signature is invalid or unparseable in some way.
     */
    public static TxEd25519Signature decodeFromKryptohash(byte[] bytes) throws VerificationException {
        if (bytes == null)
            throw new VerificationException("Null signature");
        if (bytes.length == 0)
            throw new VerificationException("Zero length signature");

        byte [] data = Arrays.copyOf(bytes, bytes.length-1);
        Ed25519Key.stdEd25519Sig sig = new Ed25519Key.stdEd25519Sig(data);

        // In Kryptohash, any value of the final byte is valid, but not necessarily canonical. See javadocs for
        // isEncodingCanonical to learn more about this. So we must store the exact byte found.
        return new TxEd25519Signature(sig.getBigInteger(), bytes[bytes.length - 1]);
    }
}
