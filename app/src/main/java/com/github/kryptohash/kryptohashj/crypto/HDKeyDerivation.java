/**
 * Copyright 2013 Matija Mazi.
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

//import com.github.kryptohash.kryptohashj.core.ECKey;
import com.github.kryptohash.kryptohashj.core.Ed25519Key;
import com.github.kryptohash.kryptohashj.core.Utils;
import com.google.common.collect.ImmutableList;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import ch.qos.logback.core.net.SocketConnector;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

/**
 * Implementation of the <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP 32</a>
 * deterministic wallet child key generation algorithm.
 */
public final class HDKeyDerivation {
    // Some arbitrary random number. Doesn't matter what it is.
    private static final BigInteger RAND_INT = new BigInteger(256, new SecureRandom());

    private HDKeyDerivation() { }

    /**
     * Child derivation may fail (although with extremely low probability); in such case it is re-attempted.
     * This is the maximum number of re-attempts (to avoid an infinite loop in case of bugs etc.).
     */
    public static final int MAX_CHILD_DERIVATION_ATTEMPTS = 100;

    public static final HMac MASTER_HMAC_SHA512 = HDUtils.createHmacSha512Digest("Kryptohash seed".getBytes());

    /**
     * Generates a new deterministic key from the given seed, which can be any arbitrary byte array. However resist
     * the temptation to use a string as the seed - any key derived from a password is likely to be weak and easily
     * broken by attackers (this is not theoretical, people have had money stolen that way). This method checks
     * that the given seed is at least 64 bits long.
     *
     * @throws HDDerivationException if generated master key is invalid (private key 0 or >= n).
     * @throws IllegalArgumentException if the seed is less than 8 bytes and could be brute forced.
     */
    public static DeterministicEd25519Key createMasterPrivateKey(byte[] seed) throws HDDerivationException {
        checkArgument(seed.length > 8, "Seed is too short and could be brute forced");
        // Calculate I = HMAC-SHA512(key="Kryptohash seed", msg=S)
        byte[] i = HDUtils.hmacSha512(MASTER_HMAC_SHA512, seed);
        // Split I into two 32-byte sequences, Il and Ir.
        // Use Il as master secret key, and Ir as master chain code.
        checkState(i.length == 64, i.length);
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] ir = Arrays.copyOfRange(i, 32, 64);
        Arrays.fill(i, (byte)0);
        DeterministicEd25519Key masterPrivKey = createMasterPrivKeyFromBytes(il, ir);
        Arrays.fill(il, (byte)0);
        Arrays.fill(ir, (byte)0);
        // Child deterministic keys will chain up to their parents to find the keys.
        masterPrivKey.setCreationTimeSeconds(Utils.currentTimeSeconds());
        return masterPrivKey;
    }

    /**
     * @throws HDDerivationException if privKeyBytes is invalid (0 or >= n).
     */
    public static DeterministicEd25519Key createMasterPrivKeyFromBytes(byte[] privKeyBytes, byte[] chainCode) throws HDDerivationException {
        //BigInteger priv = new BigInteger(1, privKeyBytes);
        assertNonZero(new BigInteger(1, privKeyBytes), "Generated master key is invalid.");
        //assertLessThanN(priv, "Generated master key is invalid.");
        return new DeterministicEd25519Key(ImmutableList.<ChildNumber>of(), chainCode, privKeyBytes, null);
    }

    /*
    public static DeterministicKey createMasterPubKeyFromBytes(byte[] pubKeyBytes, byte[] chainCode) {
        return new DeterministicKey(ImmutableList.<ChildNumber>of(), chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), pubKeyBytes), null, null);
    }
    */

    /**
     * Derives a key given the "extended" child number, ie. the 0x80000000 bit of the value that you
     * pass for <code>childNumber</code> will determine whether to use hardened derivation or not.
     * Consider whether your code would benefit from the clarity of the equivalent, but explicit, form
     * of this method that takes a <code>ChildNumber</code> rather than an <code>int</code>, for example:
     * <code>deriveChildKey(parent, new ChildNumber(childNumber, true))</code>
     * where the value of the hardened bit of <code>childNumber</code> is zero.
     */
    public static DeterministicEd25519Key deriveChildKey(DeterministicEd25519Key parent, int childNumber) {
        return deriveChildKey(parent, new ChildNumber(childNumber));
    }

    /**
     * Derives a key of the "extended" child number, ie. with the 0x80000000 bit specifying whether to use
     * hardened derivation or not. If derivation fails, tries a next child.
     */
    public static DeterministicEd25519Key deriveThisOrNextChildKey(DeterministicEd25519Key parent, int childNumber) {
        int nAttempts = 0;
        ChildNumber child = new ChildNumber(childNumber);
        boolean isHardened = child.isHardened();
        while (nAttempts < MAX_CHILD_DERIVATION_ATTEMPTS) {
            try {
                child = new ChildNumber(child.num() + nAttempts, isHardened);
                return deriveChildKey(parent, child);
            } catch (HDDerivationException ignore) { }
            nAttempts++;
        }
        throw new HDDerivationException("Maximum number of child derivation attempts reached, this is probably an indication of a bug.");

    }

    /**
     * @throws HDDerivationException if private derivation is attempted for a public-only parent key, or
     * if the resulting derived key is invalid (eg. private key == 0).
     */
    public static DeterministicEd25519Key deriveChildKey(DeterministicEd25519Key parent, ChildNumber childNumber) throws HDDerivationException {
        RawKeyBytes rawKey;
        if (parent.isPubKeyOnly()) {
            rawKey = deriveChildKeyBytesFromPublic(parent, childNumber);
            return new DeterministicEd25519Key(
                    HDUtils.append(parent.getPath(), childNumber),
                    rawKey.chainCode,
                    new BigInteger(1, rawKey.keyBytes),
                    null,
                    parent);
        } else {
            if (childNumber.isHardened()) {
                rawKey = deriveChildKeyBytesFromEdSeed(parent, childNumber);
            } else {
                rawKey = deriveChildKeyBytesFromPrivate(parent, childNumber);
            }
            return new DeterministicEd25519Key(
                    HDUtils.append(parent.getPath(), childNumber),
                    rawKey.chainCode,
                    rawKey.keyBytes,
                    parent);
        }
    }

    public static RawKeyBytes deriveChildKeyBytesFromEdSeed(DeterministicEd25519Key parent, ChildNumber childNumber) throws HDDerivationException {
        checkArgument(parent.hasSeed());
        checkArgument(childNumber.isHardened(), "Can't use seed derivation for non-hardened keys.");
        ByteBuffer data = ByteBuffer.allocate(37);
            data.put(parent.getSeedBytes33());
        data.putInt(childNumber.i());
        byte[] i = HDUtils.hmacSha512(parent.getChainCode(), data.array());
        assert i.length == 64 : i.length;
        byte[] priv = Arrays.copyOfRange(i, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
        return new RawKeyBytes(priv, chainCode);
        }

    public static RawKeyBytes deriveChildKeyBytesFromPrivate(DeterministicEd25519Key parent, ChildNumber childNumber) throws HDDerivationException {
        checkArgument(parent.hasPrivKey());
        ByteBuffer data = ByteBuffer.allocate(69);
        data.put(parent.getPrivKeyBytes65());
        data.putInt(childNumber.i());
        byte[] i = HDUtils.hmacSha512(parent.getChainCode(), data.array());
        assert i.length == 64 : i.length;
        byte[] priv = Arrays.copyOfRange(i, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
        return new RawKeyBytes(priv, chainCode);
    }

    public static RawKeyBytes deriveChildKeyBytesFromPublic(DeterministicEd25519Key parent, ChildNumber childNumber) throws HDDerivationException {
        checkArgument(!childNumber.isHardened(), "Can't use private derivation with public keys only.");
        byte[] parentPublicKey = parent.getPubKeyBytes33();
        assert parentPublicKey.length == 33 : parentPublicKey.length;
        ByteBuffer data = ByteBuffer.allocate(37);
        data.put(parentPublicKey);
        data.putInt(childNumber.i());
        byte[] i = HDUtils.hmacSha512(parent.getChainCode(), data.array());
        assert i.length == 64 : i.length;
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
        return new RawKeyBytes(il, chainCode);
    }

    private static void assertNonZero(BigInteger integer, String errorMessage) {
        if (integer.equals(BigInteger.ZERO))
            throw new HDDerivationException(errorMessage);
    }

    public static class RawKeyBytes {
        public final byte[] keyBytes, chainCode;

        public RawKeyBytes(byte[] keyBytes, byte[] chainCode) {
            this.keyBytes = keyBytes;
            this.chainCode = chainCode;
        }
    }
}
