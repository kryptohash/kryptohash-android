/*
 * Copyright 2015 Kryptohash developers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.kryptohash.kryptohashj.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import com.github.aelstad.keccakj.core.KeccackSponge;
import com.github.aelstad.keccakj.kryptohash.*;
//import com.github.aelstad.keccakj.kryptohash.provider.KryptohashProvider;

/**
 * Various hashing utilities used in the Kryptohash system.
 */
public class KryptohashUtils {
    private final static int KRATE = 120;
    private final static int KPOW_MUL = 546;
    public final static int KPROOF_OF_WORK_SZ = KPOW_MUL * KRATE;

/*  Security provider did not work with Android :-(
    If somebody can figure this one out, be my guest.

   private static final String SHA3_224 = "SHA3-224";
   private static final String SHA3_256 = "SHA3-256";
   private static final String SHAKE160 = "SHAKE160";
   private static final String SHAKE320 = "SHAKE320";

   static {
       Security.addProvider(new KryptohashProvider());
   }

   // Sha3-224

   public static Sha3_224Hash Sha3_224(byte[] data) {
       MessageDigest digest;
       digest = getSha3_224Digest();
       digest.update(data, 0, data.length);
       return Sha3_224Hash.of(digest.digest());
   }

   private static MessageDigest getSha3_224Digest() {
       try {
           return MessageDigest.getInstance(SHA3_224);
       } catch (NoSuchAlgorithmException e) {
           throw new RuntimeException(e); //cannot happen
       }
   }

   public static Sha3_224Hash doubleSha3_224(byte[] data) {
       return doubleSha3_224(data, 0, data.length);
   }

   public static Sha3_224Hash doubleSha3_224TwoBuffers(byte[] data1, byte[] data2) {
       MessageDigest digest;
       digest = getSha3_224Digest();
       digest.update(data1, 0, data1.length);
       digest.update(data2, 0, data2.length);
       return new Sha3_224Hash(digest.digest(digest.digest()));
   }

   public static Sha3_224Hash doubleSha3_224(byte[] data, int offset, int length) {
       MessageDigest digest;
       digest = getSha3_224Digest();
       digest.update(data, offset, length);
       return new Sha3_224Hash(digest.digest(digest.digest()));
   }


   // Sha3-256

   public static Sha3_256Hash Sha3_256(byte[] data) {
      MessageDigest digest;
      digest = getSha3_256Digest();
      digest.update(data, 0, data.length);
      return Sha3_256Hash.of(digest.digest());
   }

   public static Sha3_256Hash Sha3_256(byte[] data1, byte[] data2) {
      MessageDigest digest;
      digest = getSha3_256Digest();
      digest.update(data1, 0, data1.length);
      digest.update(data2, 0, data2.length);
      return new Sha3_256Hash(digest.digest());
   }

   private static MessageDigest getSha3_256Digest() {
      try {
         return MessageDigest.getInstance(SHA3_256);
      } catch (NoSuchAlgorithmException e) {
         throw new RuntimeException(e); //cannot happen
      }
   }

   public static Sha3_256Hash doubleSha3_256(byte[] data) {
      return doubleSha3_256(data, 0, data.length);
   }

   public static Sha3_256Hash doubleSha3_256TwoBuffers(byte[] data1, byte[] data2) {
      MessageDigest digest;
      digest = getSha3_256Digest();
      digest.update(data1, 0, data1.length);
      digest.update(data2, 0, data2.length);
      return new Sha3_256Hash(digest.digest(digest.digest()));
   }

   public static Sha3_256Hash doubleSha3_256(byte[] data, int offset, int length) {
      MessageDigest digest;
      digest = getSha3_256Digest();
      digest.update(data, offset, length);
      return new Sha3_256Hash(digest.digest(digest.digest()));
   }


   // Shake160
   
   public static Shake160Hash Shake160(byte[] data) {
      MessageDigest digest;
      digest = getShake160Digest();
      digest.update(data, 0, data.length);
      return Shake160Hash.of(digest.digest());
   }

   public static Shake160Hash Shake160(byte[] data1, byte[] data2) {
      MessageDigest digest;
      digest = getShake160Digest();
      digest.update(data1, 0, data1.length);
      digest.update(data2, 0, data2.length);
      return new Shake160Hash(digest.digest());
   }

   private static MessageDigest getShake160Digest() {
      try {
         return MessageDigest.getInstance(SHAKE160);
      } catch (NoSuchAlgorithmException e) {
         throw new RuntimeException(e); //cannot happen
      }
   }   

   // Shake320

    public static Shake320Hash Shake320(byte[] data) {
        MessageDigest digest;
        digest = getShake320Digest();
        digest.update(data, 0, data.length);
        return Shake320Hash.of(digest.digest());
    }

    public static Shake320Hash Shake320(byte[] data1, byte[] data2) {
        MessageDigest digest;
        digest = getShake320Digest();
        digest.update(data1, 0, data1.length);
        digest.update(data2, 0, data2.length);
        return new Shake320Hash(digest.digest());
    }

    private static MessageDigest getShake320Digest() {
        try {
            return MessageDigest.getInstance(SHAKE320);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e); //cannot happen
        }
    }

    public static Shake320Hash doubleShake320(byte[] data, int offset, int length) {
        MessageDigest digest;
        digest = getShake320Digest();
        digest.update(data, offset, length);
        return new Shake320Hash(digest.digest(digest.digest()));
    }
*/

    // Without using Security Providers

    // Shake160

    public static Shake160Hash Shake160(byte[] data) {
        MessageDigest digest;
        digest = new SHAKE160();
        digest.update(data, 0, data.length);
        return Shake160Hash.of(digest.digest());
    }

    public static Shake160Hash Shake160(byte[] data1, byte[] data2) {
        MessageDigest digest;
        digest = new SHAKE160();
        digest.update(data1, 0, data1.length);
        digest.update(data2, 0, data2.length);
        return new Shake160Hash(digest.digest());
    }


    // Shake320

    public static Shake320Hash Shake320(byte[] data) {
        MessageDigest digest;
        digest = new SHAKE320();
        digest.update(data, 0, data.length);
        return Shake320Hash.of(digest.digest());
    }

    public static Shake320Hash Shake320(byte[] data1, byte[] data2) {
        MessageDigest digest;
        digest = new SHAKE320();
        digest.update(data1, 0, data1.length);
        digest.update(data2, 0, data2.length);
        return new Shake320Hash(digest.digest());
    }

    public static Shake320Hash Shake320(byte[] data, int offset, int length) {
        MessageDigest digest;
        digest = new SHAKE320();
        digest.update(data, offset, length);
        return new Shake320Hash(digest.digest());
    }

    // KShake320

    public static Shake320Hash KShake320v1(byte[] data) {
        KeccackSponge sponge = new KSHAKE320();
        sponge.getAbsorbStream().write(data);
        byte[] digest = new byte[KPROOF_OF_WORK_SZ];
        sponge.getSqueezeStream().read(digest);
        sponge.reset();
        return Shake320(digest);
    }

    public static Shake320Hash KShake320v2(byte[] data) {
        KeccackSponge sponge = new KSHAKE320();
        sponge.getAbsorbStream().write(data);
        byte[] digest = new byte[KPROOF_OF_WORK_SZ];
        sponge.getSqueezeStream().read(digest);
        sponge.reset();
        /*
        // Version 2. Swap blocks in chunks of KRATE size.
        */
        byte[] scratchpad = new byte[KPROOF_OF_WORK_SZ];
        int offset1 = KPROOF_OF_WORK_SZ;
        int offset2 = 0;
        int i;
        for (i = 0; i < KPOW_MUL; i++) {
            offset1 -= KRATE;
            System.arraycopy(digest, offset1, scratchpad, offset2, KRATE);
            offset2 += KRATE;
        }
        return Shake320(scratchpad);
    }

    // Sha3-224

    public static Sha3_224Hash Sha3_224(byte[] data) {
        MessageDigest digest;
        digest = new SHA3_224();
        digest.update(data, 0, data.length);
        return Sha3_224Hash.of(digest.digest());
    }

    public static Sha3_224Hash doubleSha3_224(byte[] data) {
        return doubleSha3_224(data, 0, data.length);
    }

    public static Sha3_224Hash doubleSha3_224TwoBuffers(byte[] data1, byte[] data2) {
        MessageDigest digest;
        digest = new SHA3_224();
        digest.update(data1, 0, data1.length);
        digest.update(data2, 0, data2.length);
        return new Sha3_224Hash(digest.digest(digest.digest()));
    }

    public static Sha3_224Hash doubleSha3_224(byte[] data, int offset, int length) {
        MessageDigest digest;
        digest = new SHA3_224();
        digest.update(data, offset, length);
        return new Sha3_224Hash(digest.digest(digest.digest()));
    }

    // Sha3-256

    public static Sha3_256Hash Sha3_256(byte[] data) {
        MessageDigest digest;
        digest = new SHA3_256();
        digest.update(data, 0, data.length);
        return Sha3_256Hash.of(digest.digest());
    }

    public static Sha3_256Hash Sha3_256(byte[] data1, byte[] data2) {
        MessageDigest digest;
        digest = new SHA3_256();
        digest.update(data1, 0, data1.length);
        digest.update(data2, 0, data2.length);
        return new Sha3_256Hash(digest.digest());
    }

    public static Sha3_256Hash doubleSha3_256(byte[] data) {
        return doubleSha3_256(data, 0, data.length);
    }

    public static Sha3_256Hash doubleSha3_256TwoBuffers(byte[] data1, int offset1, int length1,
                                                        byte[] data2, int offset2, int length2) {
        MessageDigest digest;
        digest = new SHA3_256();
        digest.update(data1, offset1, length1);
        digest.update(data2, offset2, length2);
        return new Sha3_256Hash(digest.digest(digest.digest()));
    }

    public static Sha3_256Hash doubleSha3_256(byte[] data, int offset, int length) {
        MessageDigest digest;
        digest = new SHA3_256();
        digest.update(data, offset, length);
        return new Sha3_256Hash(digest.digest(digest.digest()));
    }

}
