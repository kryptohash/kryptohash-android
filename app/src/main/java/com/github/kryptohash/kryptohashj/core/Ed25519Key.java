/**
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * COpyright 2015 Kryptohash Developers
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

package com.github.kryptohash.kryptohashj.core;

import com.github.kryptohash.kryptohashj.crypto.*;
import com.github.punisher.NaCl.Ed25519;
import com.github.punisher.NaCl.CryptoBytes;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;
import com.google.common.base.Objects.ToStringHelper;
import com.google.common.base.Preconditions;
import com.google.common.primitives.UnsignedBytes;
//import org.bitcoin.NativeSecp256k1;
import com.github.kryptohash.kryptohashj.wallet.Protos;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.asn1.*;
import org.spongycastle.asn1.x9.X9IntegerConverter;
//import org.spongycastle.crypto.digests.SHA256Digest;
//import org.spongycastle.crypto.ec.CustomNamedCurves;
//import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.*;
//import org.spongycastle.crypto.signers.ECDSASigner;
//import org.spongycastle.crypto.signers.HMacDSAKCalculator;
//import org.spongycastle.math.ec.ECAlgorithms;
//import org.spongycastle.math.ec.ECPoint;
//import org.spongycastle.math.ec.FixedPointUtil;
//import org.spongycastle.math.ec.custom.sec.SecP256K1Curve;
import org.spongycastle.util.encoders.Base64;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Comparator;

import static com.google.common.base.Preconditions.*;

/**
 * <p>Represents an elliptic curve public and private key, usable for digital signatures but not encryption.
 * Creating a new Ed25519Key with the empty constructor will generate a new random key pair. Other static methods can be
 * used when you already have the public or private parts. If you create a key with only the public part, you can check
 * signatures but not create them.</p>
 *
 * <p>Ed25519Key also provides access to Kryptohash Core compatible text message signing, as accessible via the UI or JSON-RPC.
 * This is slightly different to signing raw bytes - if you want to sign your own data and it won't be exposed as
 * text to people, you don't want to use this. If in doubt, ask on the mailing list.</p>
 *
 */
public class Ed25519Key implements EncryptableItem, Serializable {
    private static final Logger log = LoggerFactory.getLogger(Ed25519.class);
    public static final byte Ed25519PublicKeyEncodedHeader = 0x02;
    public static final int Ed25519PublicKeyEncodedSize = Ed25519.PublicKeySizeInBytes + 1;

    /** Sorts oldest keys first, newest last. */
    public static final Comparator<Ed25519Key> AGE_COMPARATOR = new Comparator<Ed25519Key>() {

        @Override
        public int compare(Ed25519Key k1, Ed25519Key k2) {
        if (k1.creationTimeSeconds == k2.creationTimeSeconds)
            return 0;
        else
            return k1.creationTimeSeconds > k2.creationTimeSeconds ? 1 : -1;
        }
    };

    /** Compares pub key bytes using {@link com.google.common.primitives.UnsignedBytes#lexicographicalComparator()} */
    public static final Comparator<Ed25519Key> PUBKEY_COMPARATOR = new Comparator<Ed25519Key>() {
        private Comparator<byte[]> comparator = UnsignedBytes.lexicographicalComparator();

        @Override
        public int compare(Ed25519Key k1, Ed25519Key k2) {
            return comparator.compare(k1.getPubKey(), k2.getPubKey());
        }
    };

    private static final SecureRandom secureRandom;
    private static final long serialVersionUID = -728224901792295831L;

    static {
        secureRandom = new SecureRandom();
    }

    private boolean isValid = false;

    // The Ed25519 seed
    protected BigInteger EdSeed;

    // The key.
    protected BigInteger priv;  // A field element.
    protected BigInteger pub;

    // Creation time of the key in seconds since the epoch, or zero if the key was deserialized from a version that did
    // not have this field.
    protected long creationTimeSeconds;

    protected KeyCrypter keyCrypter;
    protected EncryptedData encryptedSeed;

    private boolean seedEncrypted = false;

    // Transient because it's calculated on demand/cached.
    private transient byte[] pubKeyHash;

    /**
     * Generates an entirely new keypair.
     */
    public Ed25519Key() {
        this(secureRandom);
    }

    public Ed25519Key(SecureRandom secureRandom) {
        byte[] Seed = secureRandom.generateSeed(32);
        try {
            byte[] pub = Ed25519.PublicKeyFromSeed(Seed);
            this.pub = new BigInteger(1, pub);
            byte[] priv = Ed25519.ExpandedPrivateKeyFromSeed(Seed);
            this.priv = new BigInteger(1, priv);

            this.EdSeed = new BigInteger(1, Seed);
            this.isValid = true;
        } catch (Exception e) {
            this.isValid = false;
        }
    }

    /**
     * Creates a private/public keypair with the given the seed.
     */
    protected Ed25519Key(byte[] Seed) {
        try {
            byte[] pub = Ed25519.PublicKeyFromSeed(Seed);
            this.pub = new BigInteger(1, pub);
            byte[] priv = Ed25519.ExpandedPrivateKeyFromSeed(Seed);
            this.priv = new BigInteger(1, priv);

            this.EdSeed = new BigInteger(1, Seed);
            this.isValid = true;
        } catch (Exception e) {
            this.isValid = false;
        }
    }

    protected Ed25519Key(@Nullable BigInteger _priv, @Nullable BigInteger _pub) {
        if (_priv != null) {
            // Try and catch buggy callers or bad key imports, etc. Zero and one are special because these are often
            // used as sentinel values and because scripting languages have a habit of auto-casting true and false to
            // 1 and 0 or vice-versa. Type confusion bugs could therefore result in private keys with these values.
            checkArgument(!_priv.equals(BigInteger.ZERO));
            checkArgument(!_priv.equals(BigInteger.ONE));
            this.priv = _priv;
        }

        if (_pub != null) {
            // Try and catch buggy callers or bad key imports, etc. Zero and one are special because these are often
            // used as sentinel values and because scripting languages have a habit of auto-casting true and false to
            // 1 and 0 or vice-versa. Type confusion bugs could therefore result in private keys with these values.
            checkArgument(!_pub.equals(BigInteger.ZERO));
            checkArgument(!_pub.equals(BigInteger.ONE));
        }
        this.pub = checkNotNull(_pub);
        this.isValid = true;
    }

    protected Ed25519Key(BigInteger _priv) {
        checkNotNull(_priv);
        checkArgument(!_priv.equals(BigInteger.ZERO));
        checkArgument(!_priv.equals(BigInteger.ONE));
        this.priv = _priv;
        this.isValid = true;
    }


    public boolean isValid() {
        return isValid;
    }

    public boolean isSeedEncrypted() {
        return seedEncrypted;
    }

    /**
     * Creates Ed25519Key containing only Private/Public key pair. Assumes that the seed exists.
     */
    public Ed25519Key getPrivateAndPublicKeys() {
        if (!isValid() || EdSeed == null || isSeedEncrypted())
            throw new RuntimeException("Seed not available");

        Ed25519Key key = new Ed25519Key(EdSeed.toByteArray());
        return new Ed25519Key(key.priv, key.pub);
    }

    /**
     * Creates an Ed25519Key given the seed only. The private/public keypair is calculated from it.
     */
    public static Ed25519Key fromSeed(byte[] seedBytes) {
        return new Ed25519Key(seedBytes);
    }

    /**
     * Creates an Ed25519Key that simply trusts the caller to ensure that private and public keys have the right values
     * already.
     */
    public static Ed25519Key fromPrivateAndPublic(BigInteger priv, BigInteger pub) {
        return new Ed25519Key(priv, pub);
    }

    /**
     * Creates an Ed25519Key that simply trusts the caller to ensure that point is really the result of multiplying the
     * generator point by the private key. This is used to speed things up when you know you have the right values
     * already. The compression state of the point will be preserved.
     */
    public static Ed25519Key fromPrivateAndPublic(byte[] priv, byte[] pub) {
        checkNotNull(priv);
        checkNotNull(pub);
        return new Ed25519Key(new BigInteger(1, priv), new BigInteger(1, pub));
    }

    /**
     * Creates an Ed25519Key given the encoded Public key.
     * It cannot be used for signing, only for verifying signatures.
     */
    public static Ed25519Key fromPublicOnly(byte[] pubKey) {
        if (pubKey == null || pubKey.length != Ed25519PublicKeyEncodedSize || pubKey[0] != 0x02)
            throw new RuntimeException("Invalid public key");
        byte[] pubBytes = new byte[Ed25519.PublicKeySizeInBytes];
        System.arraycopy(pubKey, 1, pubBytes, 0, pubBytes.length);
        return new Ed25519Key(null, new BigInteger(1, pubBytes));
    }

    /**
     * Create a new Ed25519Key with an encrypted Seed, a public key and a KeyCrypter.
     *
     * @param encryptedSeed The seed, encrypted,
     * @param pubKey The public key, encoded,
     * @param keyCrypter The KeyCrypter that will be used, with an AES key, to encrypt and decrypt the private key
     */
    @Deprecated
    public Ed25519Key(EncryptedData encryptedSeed, byte[] pubKey, KeyCrypter keyCrypter) {
        if (pubKey == null || pubKey.length != Ed25519PublicKeyEncodedSize || pubKey[0] != 0x02)
            throw new RuntimeException("Invalid public key");

        byte[] pubBytes = new byte[Ed25519.PublicKeySizeInBytes];
        System.arraycopy(pubKey, 1, pubBytes, 0, pubBytes.length);
        this.pub = new BigInteger(1, pubBytes);
        this.keyCrypter = checkNotNull(keyCrypter);
        this.encryptedSeed = encryptedSeed;
        this.seedEncrypted = true;
    }

    /**
     * Constructs a key that has an encrypted seed component.
     */
    public static Ed25519Key fromEncrypted(EncryptedData encryptedSeed, KeyCrypter crypter, byte[] pubKey) {
        Ed25519Key key = fromPublicOnly(pubKey);
        key.encryptedSeed = checkNotNull(encryptedSeed);
        key.keyCrypter = checkNotNull(crypter);
        key.seedEncrypted = true;
        return key;
    }

    /**
     * Returns true if this key doesn't have unencrypted access to private key bytes. This may be because it was never
     * given any private key bytes to begin with (a watching key), or because the key is encrypted. You can use
     * {@link #isEncrypted()} to tell the cases apart.
     */
    public boolean isPubKeyOnly() {
        return isValid() && priv == null;
    }

    /**
     * Returns true if this key has unencrypted access to private key bytes. Does the opposite of
     * {@link #isPubKeyOnly()}.
     */
    public boolean hasPrivKey() {
        return isValid() && priv != null;
    }

    /**
     * Returns true if this key has unencrypted access to Ed25519 Seed bytes.
     */
    public boolean hasSeed() {
        return isValid() && EdSeed != null && !isSeedEncrypted();
    }

    public BigInteger getSeed() {
        if (!hasSeed())
            throw new RuntimeException("Invalid Seed");
        return EdSeed;
    }


    /**
     * Returns public key bytes from the given Seed. To convert a byte array into a BigInteger, use <tt>
     * new BigInteger(1, bytes);</tt>
     */
    public static byte[] publicKeyFromSeed(byte[] Seed) {
        Ed25519Key key = fromSeed(Seed);
        return key.getPubKey();
    }

    /** Gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getPubKeyHash() {
        if (!isValid())
            throw new RuntimeException("Invalid public key");

        if (pubKeyHash == null) {
            byte[] pubKey = getPubKeyEncoded();
            pubKeyHash = KryptohashUtils.Shake160(pubKey).getBytes();
        }
        return pubKeyHash;
    }

    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is <b>not</b> the same
     * as the pubKeyHash/address.
     */
    public byte[] getPubKey() {
        if (pub == null)
            return null;
        if (!isValid())
            throw new RuntimeException("Invalid public key");

        return Utils.bigIntegerToBytes(this.pub, Ed25519.PublicKeySizeInBytes);
    }

    public byte[] getPubKeyEncoded() {
        byte[] pubKey = new byte[Ed25519.PublicKeySizeInBytes + 1];
        pubKey[0] = (byte)Ed25519PublicKeyEncodedHeader;
        System.arraycopy(getPubKey(), 0, pubKey, 1, Ed25519.PublicKeySizeInBytes);
        return pubKey;
    }

    /**
     * Gets the private key in the form of an integer field element.
     * @throws java.lang.IllegalStateException if the private key bytes are not available.
     */
    public BigInteger getPrivKey() {
        if (!isValid() || priv == null)
            return null;
        return priv;
    }

    /**
     * Returns whether this key is using the compressed form or not. Compressed pubkeys are only 33 bytes, not 64.
     */
    public boolean isCompressed() {
        return false;
    }

    /**
     * Returns the address that corresponds to the public part of this Ed25519Key. Note that an address is derived from
     * the shake160 hash of the public key and is not the public key itself (which is too large to be convenient).
     */
    public Address toAddress(NetworkParameters params) {
        return new Address(params, getPubKeyHash());
    }

    /**
     * Groups the components that make up a signature, and provides a way to encode to a special Kryptohash form.
     */
    public static class stdEd25519Sig {
        /** This Class encodes ed25519 signatures with the following serial structure:
         *
         *  Serial size = 104 bytes long **
         *
         *  ** Signature prefix (4 Bytes) **
         *  Offset  Name         Data Type       Description
         *    0  Magic/nZeroByte   uchar      The 5 most significant bits must be equal to '10100' for ed25519 signatures.
         *                                    The 3 least significant bits must be equal to '000' to indicate that the signature
         *                                    includes a checksum of the first n-bytes of SHA3-256(SHA3-256(prefix+signature+privkey)).
         *
         *    1  SignatureLen      uchar      Length of the signature field (Fixed to 64 bytes for ed25519)
         *
         *    2  PubkeyLen         uchar      Length of the Public Key field (Fixed to 32 bytes for ed25519)
         *
         *    3  Checksum/Nonce    uchar      Length of the Checksum or Nonce field (Fixed to 4 bytes for ed25119)
         *
         *
         *  ** Signature (64 bytes for ed25519) **
         *   Offset          Name             Data Type
         *  4 to 67        signature          uchar[64]
         *
         *  ** PublicKey (32 bytes for ed25519) **
         *   Offset          Name             Data Type
         *  68 to 99      public key          uchar[32]
         *
         *  ** Signature Suffix (4 bytes for ed25519) **
         *   Offset          Name             Data Type
         *  100 to 103   Checksum/Nonce       uint32_t
         *
         */

        /** Header of the standard Kryptohash signature */
        public static final byte[] stdHeaderBytes = new byte[]{(byte)0xa0, (byte)0x40, (byte)0x20, (byte)0x04};
        /** Length of the standard Kryptohash signature */
        public static final int stdSigLen = 104;
        /** Length of the checksum */
        public static final int stdChecksumLen = 4;

        private boolean isValid = false;

        /** The signature. */
        public BigInteger sig;

        /**
         * Constructs a signature with the given BigInteger.
         */
        public stdEd25519Sig(BigInteger sig) {
            this(Utils.bigIntegerToBytes(sig, stdSigLen));
        }

        /**
         * Constructs a signature with the given encoded byte array.
         * It checks the encoding.
         */
        public stdEd25519Sig(byte[] s) {
            if (this.isSigValid(s)) {
                this.sig = new BigInteger(1, s);
                this.isValid = true;
            }
            else {
                throw new RuntimeException("Bad signature encoding");
            }
        }

        /**
         * Constructs a signature with the given byte arrays for ed25519 signature and public key.
         * Caller must ensure the signature and public key are valid. Only their length are checked.
         */
        public stdEd25519Sig(byte[] sig, byte[] pub) {
            if (sig == null || pub == null || sig.length != Ed25519.SignatureSizeInBytes || pub.length != Ed25519.PublicKeySizeInBytes) {
                log.error("Could not construct a Ed25519 signature");
                isValid = false;
            }

            byte[] data = new byte[stdSigLen - stdChecksumLen];
            // Copy header
            System.arraycopy(stdHeaderBytes, 0, data, 0, stdHeaderBytes.length);
            // Copy ed25119 signature
            System.arraycopy(sig, 0, data, 4,  Ed25519.SignatureSizeInBytes);
            // Copy private key
            System.arraycopy(pub, 0, data, 68, Ed25519.PrivateKeySeedSizeInBytes);
            // Calculate checksum
            byte[] checkSum = calcChecksum(data);
            // Copy data into a new larger array.
            byte[] s = Arrays.copyOf(data, stdSigLen);
            // Add checksum to the signature
            System.arraycopy(checkSum, 0, s, stdSigLen - stdChecksumLen, stdChecksumLen);
            // Save the signature as BigInteger
            this.sig = new BigInteger(1, s);
            // We are good to go.
            isValid = true;
        }

        /* Constructs a dummy "invalid" signature with random byte arrays.
         * This can be useful when you want to fill out a transaction to be of the right size
         * (e.g. for fee calculations) but don't have the requisite signing key yet and will fill out the
         * real signature later.
         */
        public stdEd25519Sig() {
            this(secureRandom.generateSeed(Ed25519.SignatureSizeInBytes), secureRandom.generateSeed(Ed25519.PublicKeySizeInBytes));
        }

        public boolean isValid() {
            return isValid;
        }

        public BigInteger getBigInteger() {
            if (sig == null)
                throw new RuntimeException("Null Ed25519 sig");
            return sig;
        }

        public byte[] getByteArray() {
            if (sig == null) {
                log.error("Null Ed25519 signature");
                return null;
            }
            // Normalize Signature
			byte[] s = Utils.bigIntegerToBytes(this.sig, stdSigLen);
            if (!isSigValid(s)) {
                log.error("Bad Ed25519 signature");
                return null;
			}
            return s;
        }

        /* Returns array containing raw Ed25519 Public Key (32 bytes) */
        public byte[] getPubKey() {
            byte[] s = getByteArray();
            checkNotNull(s);
            byte[] pub = new byte[Ed25519.PublicKeySizeInBytes];
            System.arraycopy(s, 68, pub, 0, pub.length);
            return pub;
        }

        /* Returns array containing Public Key with header (33 bytes) */
        public byte[] getPubKeyEncoded() {
            byte[] s = getByteArray();
            checkNotNull(s);
            byte[] pub = new byte[Ed25519PublicKeyEncodedSize];
            pub[0] = Ed25519PublicKeyEncodedHeader;
            System.arraycopy(s, 68, pub, 1, pub.length - 1);
            return pub;
        }

        /* Returns array containing raw Ed25519 Signature (64 bytes) */
        public byte[] getSignature() {
            byte[] s = getByteArray();
            checkNotNull(s);
            byte[] sig = new byte[Ed25519.SignatureSizeInBytes];
            System.arraycopy(s, 4, sig, 0, sig.length);
            return sig;
        }

        /* Calculate the double Sha3-256 of the entire signature without, of course
         * including the last 4 bytes.
         */
        private byte[] calcChecksum(byte[] data) {
            if (data.length != stdSigLen - stdChecksumLen)
                throw new RuntimeException("calcChecksum: wrong length");
            byte[] hash = KryptohashUtils.doubleSha3_256(data).getBytes();
            return Arrays.copyOf(hash, stdChecksumLen);
        }

        /**
         *  Returns true if given signature has a valid length, header and checksum.
         */
        public boolean isSigValid(byte[] s) {
            if (s == null) {
                log.error("Null Ed25519 signature");
                return false;
            }
            if (s.length != stdSigLen) {
                log.error("Signature has bad length {}", s.length);
                return false;
            }
            /* Check header */
            if ((s[0] != (byte)0xa0) || (s[1] != (byte)0x40) || (s[2] != (byte)0x20) || (s[3] != (byte)0x04)) {
                log.error("Signature has bad header");
                return false;
            }
            /* Extract the last 4 bytes of the signature which is the checksum */
            byte[] checkSum = new byte[stdChecksumLen];
            System.arraycopy(s, stdSigLen - stdChecksumLen, checkSum, 0, checkSum.length);

            /* Calculate the double Sha3-256 of the entire signature without, of course
             * including the last 4 bytes.
             */
            byte[] dataToCheck = Arrays.copyOf(s, stdSigLen - stdChecksumLen);
            byte[] result = calcChecksum(dataToCheck);
            if (!Arrays.equals(checkSum, result)) {
                log.error("Signature has bad checksum");
                return false;
            }
            return true;
        }

        public boolean isSigValid(BigInteger sig) {
            // Normalize signature
			byte[] s = Utils.bigIntegerToBytes(this.sig, stdSigLen);
            return isSigValid(s);
        }

        protected ByteArrayOutputStream byteStream() throws IOException {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            // Normalize signature
			byte[] s = Utils.bigIntegerToBytes(this.sig, stdSigLen);
            if (!isSigValid(s))
                throw new IOException("Invalid Ed25519 Signature");
            bos.write(s);
            return bos;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            stdEd25519Sig other = (stdEd25519Sig) o;
            return sig.equals(other.sig);
        }

        @Override
        public int hashCode() {
            int result = sig.hashCode();
            return result;
        }
    }

    /**
     * Signs the given hash and returns the signature as BigInteger. In the Kryptohash protocol, they are
     * encoded using a custom structure
     * @throws KeyCrypterException if this Ed25519 signature doesn't have a private part.
     */
    public stdEd25519Sig sign(Sha3_256Hash input) throws KeyCrypterException {
        return sign(input, null);
    }

    /**
     * Signs the given hash and returns the signature as BigIntegers. In the Kryptohash protocol, signatures are
     * encoded using a custom format.
     *
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @throws KeyCrypterException if there's something wrong with aesKey.
     * @throws Ed25519Key.MissingPrivateKeyException if this key cannot sign because it's pubkey only.
     */
    public stdEd25519Sig sign(Sha3_256Hash input, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        KeyCrypter crypter = getKeyCrypter();
        if (crypter != null) {
            if (aesKey == null)
                throw new KeyIsEncryptedException();
            return decrypt(aesKey).sign(input);
        } else {
            // No decryption of private key required.
            if (!isValid() || priv == null)
                throw new MissingPrivateKeyException();
        }
        return doSign(input, priv, pub);
    }

    protected stdEd25519Sig doSign(Sha3_256Hash input, BigInteger privateKeyForSigning, BigInteger pubKey) {
        checkNotNull(privateKeyForSigning);
        checkNotNull(pubKey);
        // Normalize privKey
        byte[] priv = Utils.bigIntegerToBytes(privateKeyForSigning, Ed25519.ExpandedPrivateKeySizeInBytes);

        byte[] sig;
        try {
            sig = Ed25519.Sign(input.getBytes(), priv);
        } catch (Exception e) {
            throw new RuntimeException("Signing failed");
        }

        byte[] pub = Utils.bigIntegerToBytes(pubKey, Ed25519.PublicKeySizeInBytes);
        stdEd25519Sig signature = new stdEd25519Sig(sig, pub);
        if (!signature.isValid())
            throw new RuntimeException("Signature failed. Could Not Encode Signature");

        return signature;
    }

    protected stdEd25519Sig doSign(Sha3_256Hash input, BigInteger Seed) {
        checkNotNull(Seed);
        Ed25519Key key = fromSeed(Seed.toByteArray());
        if (!key.isValid())
            throw new RuntimeException("Invalid Seed");
        return doSign(input, key.priv, key.pub);
    }

    /**
     * <p>Verifies the given ed25519 signature against the message bytes using the public key bytes.</p>
     *
     * @param data      Hash of the data to verify.
     * @param signature Kryptohash standard encoded signature.
     * @param pub       The public key bytes to use.
     */
    public static boolean verify(byte[] data, stdEd25519Sig signature, byte[] pub) {
        if (data == null || signature == null || pub == null)
            throw new NullPointerException();

        if (!signature.isValid())
            return false;

        if (!Arrays.equals(pub, signature.getPubKey()))
            return false;

        boolean result;
        try {
            result = Ed25519.Verify(signature.getSignature(), data, pub);
        } catch (Exception e) {
            result = false;
        }
        return result;
    }

    /**
     * Verifies the given ASN.1 encoded ed25519 signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature Kryptohash standard encoded signature.
     * @param pub       The public key bytes to use.
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] pub) {
        return verify(data, new stdEd25519Sig(signature), pub);
    }

    /**
     * Verifies the given encoded ed signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     */
    public boolean verify(byte[] data, byte[] signature) {
        return Ed25519Key.verify(data, signature, getPubKey());
    }

    /**
     * Verifies the given signature against a hash using the public key.
     */
    public boolean verify(Sha3_256Hash sigHash, stdEd25519Sig signature) {
        return Ed25519Key.verify(sigHash.getBytes(), signature, getPubKey());
    }

    /**
     * Returns true if the given pubkey is canonical.
     */
    public static boolean isPubKeyCanonical(byte[] pubkey) {
        if (pubkey.length != 33)
            return false;
        if (pubkey[0] != Ed25519PublicKeyEncodedHeader)
            return false;

        return true;
    }

    /**
     * Signs a text message using the standard Kryptohash messaging signing format and returns the signature as a base64
     * encoded string.
     *
     * @throws IllegalStateException if this stdEd25519Sig does not have the private part.
     * @throws KeyCrypterException if this stdEd25519Sig is encrypted and no AESKey is provided or it does not decrypt the stdEd25519Sig.
     */
    public String signMessage(String message) throws KeyCrypterException {
        return signMessage(message, null);
    }

    /**
     * Signs a text message using the standard Kryptohash messaging signing format and returns the signature as a base64
     * encoded string.
     *
     * @throws IllegalStateException if this stdEd25519Sig does not have the private part.
     * @throws KeyCrypterException if this stdEd25519Sig is encrypted and no AESKey is provided or it does not decrypt the stdEd25519Key.
     */
    public String signMessage(String message, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        byte[] data = Utils.formatMessageForSigning(message);
        Sha3_256Hash hash = KryptohashUtils.doubleSha3_256(data);
        stdEd25519Sig signature = sign(hash, aesKey);

        return new String(Base64.encode(signature.sig.toByteArray()), Charset.forName("UTF-8"));
    }

    /**
     * Given an arbitrary piece of text and a Kryptohash-format message signature encoded in base64, returns an Ed25519Key
     * containing the public key that was used to sign it. This can then be compared to the expected public key to
     * determine if the signature was correct. These sorts of signatures are compatible with the Kryptohash-Qt/kryptohashd
     * format generated by signmessage/verifymessage RPCs and GUI menu options. They are intended for humans to verify
     * their communications with each other, hence the base64 format and the fact that the input is text.
     *
     * @param message Some piece of human readable text.
     * @param signatureBase64 The Kryptohash-format message signature in base64
     * @throws SignatureException If the public key could not be recovered or if there was a signature format error.
     */
    public static Ed25519Key signedMessageToKey(String message, String signatureBase64) throws SignatureException {
        byte[] signatureEncoded;
        try {
            signatureEncoded = Base64.decode(signatureBase64);
        } catch (RuntimeException e) {
            // This is what you get back from Bouncy Castle if base64 doesn't decode :(
            throw new SignatureException("Could not decode base64", e);
        }
        // Parse the signature bytes into r/s and the selector value.
        if (signatureEncoded.length != 104)
            throw new SignatureException("Signature truncated, expected 104 bytes and got " + signatureEncoded.length);

        stdEd25519Sig sig = new stdEd25519Sig(signatureEncoded);
        Ed25519Key key = Ed25519Key.fromPublicOnly(sig.getPubKeyEncoded());
        if (key == null)
            throw new SignatureException("Could not recover public key from signature");

        return key;
    }

    /**
     * Convenience wrapper around {@link Ed25519Key#signedMessageToKey(String, String)}. If the key derived from the
     * signature is not the same as this one, throws a SignatureException.
     */
    public void verifyMessage(String message, String signatureBase64) throws SignatureException {
        Ed25519Key key = Ed25519Key.signedMessageToKey(message, signatureBase64);
        if (!key.pub.equals(pub))
            throw new SignatureException("Signature did not match for message");
    }

    /**
     * Returns a 64 byte array containing the ed25519 private key.
     * @throws com.github.kryptohash.kryptohashj.core.Ed25519Key.MissingPrivateKeyException if the private key bytes are missing/encrypted.
     */
    public byte[] getPrivKeyBytes() {
        return Utils.bigIntegerToBytes(getPrivKey(), Ed25519.ExpandedPrivateKeySizeInBytes);
    }

    /**
     * Returns a 32 byte array containing the seed.
     * @throws com.github.kryptohash.kryptohashj.core.Ed25519Key.MissingPrivateKeyException if the private key bytes are missing/encrypted.
     */
    public byte[] getSeedBytes() {
        return Utils.bigIntegerToBytes(getSeed(), Ed25519.PrivateKeySeedSizeInBytes);
    }

    /**
     * Exports the private key in the form used by the Satoshi client "dumpprivkey" and "importprivkey" commands. Use
     * the {@link com.github.kryptohash.kryptohashj.core.DumpedPrivateKey#toString()} method to get the string.
     *
     * @param params The network this key is intended for use on.
     * @return Private key bytes as a {@link DumpedPrivateKey}.
     * @throws IllegalStateException if the private key is not available.
     */
    public DumpedPrivateKey getPrivateKeyEncoded(NetworkParameters params) {
        return new DumpedPrivateKey(params, getPrivKeyBytes(), isCompressed());
    }

    /**
     * Returns the creation time of this key or zero if the key was deserialized from a version that did not store
     * that data.
     */
    @Override
    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    /**
     * Sets the creation time of this key. Zero is a convention to mean "unavailable". This method can be useful when
     * you have a raw key you are importing from somewhere else.
     */
    public void setCreationTimeSeconds(long newCreationTimeSeconds) {
        if (newCreationTimeSeconds < 0)
            throw new IllegalArgumentException("Cannot set creation time to negative value: " + newCreationTimeSeconds);

        creationTimeSeconds = newCreationTimeSeconds;
    }

    /**
     * Create an encrypted private key with the keyCrypter and the AES key supplied.
     * This method returns a new encrypted key and leaves the original unchanged.
     *
     * @param keyCrypter The keyCrypter that specifies exactly how the encrypted bytes are created.
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached as it is slow to create).
     * @return encryptedKey
     */
    public Ed25519Key encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(keyCrypter);
        final byte[] privKeyBytes = getPrivKeyBytes();
        EncryptedData encryptedPrivateKey = keyCrypter.encrypt(privKeyBytes, aesKey);
        Ed25519Key result = Ed25519Key.fromEncrypted(encryptedPrivateKey, keyCrypter, getPubKey());
        result.setCreationTimeSeconds(creationTimeSeconds);
        return result;
    }

    /**
     * Create a decrypted private key with the keyCrypter and AES key supplied. Note that if the aesKey is wrong, this
     * has some chance of throwing KeyCrypterException due to the corrupted padding that will result, but it can also
     * just yield a garbage key.
     *
     * @param keyCrypter The keyCrypter that specifies exactly how the decrypted bytes are created.
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached).
     */
    public Ed25519Key decrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(keyCrypter);
        // Check that the keyCrypter matches the one used to encrypt the keys, if set.
        if (this.keyCrypter != null && !this.keyCrypter.equals(keyCrypter))
            throw new KeyCrypterException("The keyCrypter being used to decrypt the key is different to the one that was used to encrypt it");

        checkState(!isSeedEncrypted(), "This key is not encrypted");
        byte[] unencryptedPrivateKey = keyCrypter.decrypt(encryptedSeed, aesKey);
        Ed25519Key key = Ed25519Key.fromSeed(unencryptedPrivateKey);

        if (!Arrays.equals(key.getPubKey(), getPubKey()))
            throw new KeyCrypterException("Provided AES key is wrong");

        key.setCreationTimeSeconds(creationTimeSeconds);
        return key;
    }

    /**
     * Create a decrypted private key with AES key. Note that if the AES key is wrong, this
     * has some chance of throwing KeyCrypterException due to the corrupted padding that will result, but it can also
     * just yield a garbage key.
     *
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached).
     */
    public Ed25519Key decrypt(KeyParameter aesKey) throws KeyCrypterException {
        final KeyCrypter crypter = getKeyCrypter();
        if (crypter == null)
            throw new KeyCrypterException("No key crypter available");
        return decrypt(crypter, aesKey);
    }

    /**
     * Creates decrypted private key if needed.
     */
    public Ed25519Key maybeDecrypt(@Nullable KeyParameter aesKey) throws KeyCrypterException {
        return isEncrypted() && aesKey != null ? decrypt(aesKey) : this;
    }

    /**
     * <p>Check that it is possible to decrypt the key with the keyCrypter and that the original key is returned.</p>
     *
     * <p>Because it is a critical failure if the private keys cannot be decrypted successfully (resulting of loss of all
     * bitcoins controlled by the private key) you can use this method to check when you *encrypt* a wallet that
     * it can definitely be decrypted successfully.</p>
     *
     * <p>See {@link Wallet#encrypt(KeyCrypter keyCrypter, KeyParameter aesKey)} for example usage.</p>
     *
     * @return true if the encrypted key can be decrypted back to the original key successfully.
     */
    public static boolean encryptionIsReversible(Ed25519Key originalKey, Ed25519Key encryptedKey, KeyCrypter keyCrypter, KeyParameter aesKey) {
        try {
            Ed25519Key rebornUnencryptedKey = encryptedKey.decrypt(keyCrypter, aesKey);
            byte[] originalPrivateKeyBytes = originalKey.getPrivKeyBytes();
            byte[] rebornKeyBytes = rebornUnencryptedKey.getPrivKeyBytes();
            if (!Arrays.equals(originalPrivateKeyBytes, rebornKeyBytes)) {
                log.error("The check that encryption could be reversed failed for {}", originalKey);
                return false;
            }
            return true;
        } catch (KeyCrypterException kce) {
            log.error(kce.getMessage());
            return false;
        }
    }

    /**
     * Indicates whether the private key is encrypted (true) or not (false).
     * A private key is deemed to be encrypted when there is both a KeyCrypter and the encryptedPrivateKey is non-zero.
     */
    @Override
    public boolean isEncrypted() {
        return keyCrypter != null && encryptedSeed != null && encryptedSeed.encryptedBytes.length > 0;
    }

    @Nullable
    @Override
    public Protos.Wallet.EncryptionType getEncryptionType() {
        return keyCrypter != null ? keyCrypter.getUnderstoodEncryptionType() : Protos.Wallet.EncryptionType.UNENCRYPTED;
    }

    /**
     * A wrapper for {@link #getPrivKeyBytes()} that returns null if the private key bytes are missing or would have
     * to be derived (for the HD key case).
     */
    @Override
    @Nullable
    public byte[] getSecretBytes() {
        if (hasPrivKey())
            return getPrivKeyBytes();
        else
            return null;
    }

    /** An alias for {@link #getEncryptedSeed()} */
    @Nullable
    @Override
    public EncryptedData getEncryptedData() {
        return getEncryptedSeed();
    }

    /**
     * Returns the the encrypted private key bytes and initialisation vector for this Ed25519, or null if the Ed25519
     * is not encrypted.
     */
    @Nullable
    public EncryptedData getEncryptedSeed() {
        return encryptedSeed;
    }

    /**
     * Returns the KeyCrypter that was used to encrypt to encrypt this Ed25519. You need this to decrypt the Ed25519.
     */
    @Nullable
    public KeyCrypter getKeyCrypter() {
        return keyCrypter;
    }

    public static class MissingPrivateKeyException extends RuntimeException {
    }

    public static class KeyIsEncryptedException extends MissingPrivateKeyException {
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof Ed25519Key)) return false;

        Ed25519Key other = (Ed25519Key) o;

        return Objects.equal(this.priv, other.priv)
                && Objects.equal(this.pub, other.pub)
                && Objects.equal(this.creationTimeSeconds, other.creationTimeSeconds)
                && Objects.equal(this.keyCrypter, other.keyCrypter)
                && Objects.equal(this.encryptedSeed, other.encryptedSeed);
    }

    @Override
    public int hashCode() {
        // Public keys are random already so we can just use a part of them as the hashcode. Read from the start to
        // avoid picking up the type code (compressed vs uncompressed) which is tacked on the end.
        byte[] bits = getPubKey();
        return (bits[0] & 0xFF) | ((bits[1] & 0xFF) << 8) | ((bits[2] & 0xFF) << 16) | ((bits[3] & 0xFF) << 24);
    }

    @Override
    public String toString() {
        return toString(false);
    }

    /**
     * Produce a string rendering of the Ed25519 INCLUDING the private key.
     * Unless you absolutely need the private key it is better for security reasons to just use {@link #toString()}.
     */
    public String toStringWithPrivate() {
        return toString(true);
    }

    private String toString(boolean includePrivate) {
        final ToStringHelper helper = Objects.toStringHelper(this).omitNullValues();
        helper.add("pub", Utils.HEX.encode(pub.toByteArray()));
        if (includePrivate) {
            try {
                helper.add("priv", Utils.HEX.encode(getPrivKey().toByteArray()));
            } catch (IllegalStateException e) {
                // TODO: Make hasPrivKey() work for deterministic keys and fix this.
            }
        }
        if (creationTimeSeconds > 0)
            helper.add("creationTimeSeconds", creationTimeSeconds);
        helper.add("keyCrypter", keyCrypter);
        if (includePrivate)
            helper.add("encryptedPrivateKey", encryptedSeed);
        helper.add("isEncrypted", isEncrypted());
        helper.add("isPubKeyOnly", isPubKeyOnly());
        return helper.toString();
    }
}
