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

import com.google.common.base.Preconditions;
import com.google.common.primitives.Ints;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * represents the result of a SHAKE160 hashing operation prefer to use the static
 * factory methods.
 */
public class Shake160Hash implements Serializable, Comparable<Shake160Hash> {
   private static final long serialVersionUID = 1L;

   public static final int HASH_LENGTH = 20;
   public static final Shake160Hash ZERO_HASH = of(new byte[HASH_LENGTH]);

   private final byte[] bytes;
   private int hash;

   public Shake160Hash(byte[] _bytes) {
      Preconditions.checkArgument(_bytes.length == HASH_LENGTH);
      this.bytes = _bytes;
      hash = -1;
   }

   /**
    * Creates a Shake160Hash by decoding the given hex string. It must be 40 characters long.
    */
   public Shake160Hash(String hexString) {
      Preconditions.checkArgument(hexString.length() == 2*HASH_LENGTH);
      this.bytes = Utils.HEX.decode(hexString);
   }

   public static Shake160Hash fromString(String hexString) {
      try {
         byte[] b = HexUtils.toBytes(hexString);
         if (b.length != HASH_LENGTH) {
            return null;
         }
         return new Shake160Hash(b);
      } catch (RuntimeException e) {
         // invalid hex string
         return null;
      }
   }

   /**
    * takes 20 bytes and stores them as hash. does not actually hash, this is
    * done in KryptohashUtils
    * 
    * @param _bytes
    *           to be stored
    */
   public static Shake160Hash of(byte[] _bytes) {
      return new Shake160Hash(_bytes);
   }

   public static Shake160Hash copyOf(byte[] _bytes, int offset) {
      return new Shake160Hash(_bytes, offset);
   }

   private Shake160Hash(byte[] _bytes, int offset) {
      // defensive copy, since incoming bytes is of arbitrary length
      bytes = new byte[HASH_LENGTH];
      System.arraycopy(_bytes, offset, bytes, 0, HASH_LENGTH);
      hash = -1;
   }

   @Override
   public boolean equals(Object other) {
      if (other == this) {
         return true;
      }
      if (!(other instanceof Shake160Hash))
         return false;
      return Arrays.equals(bytes, ((Shake160Hash) other).bytes);
   }

   @Override
   public int hashCode() {
      if (hash == -1) {
         final int offset = bytes.length - 4;
         hash = 0;
         for (int i = 0; i < 4; i++) {
            hash <<= 8;
            hash |= (((int) bytes[offset + i]) & 0xFF);
         }
      }
      return hash;
   }

   @Override
   public String toString() {
      return toHex();
   }

   public byte[] getBytes() {
      return bytes;
   }

   public Shake160Hash duplicate() {
        return new Shake160Hash(bytes);
    }

   @Override
   public int compareTo(Shake160Hash o) {
      for (int i = 0; i < HASH_LENGTH; i++) {
         byte myByte = bytes[i];
         byte otherByte = o.bytes[i];

         final int compare = Ints.compare(myByte, otherByte);
         if (compare != 0)
            return compare;
      }
      return 0;
   }

   public Shake160Hash reverse() {
      return new Shake160Hash(BitUtils.reverseBytes(bytes));
   }

   public int length() {
      return HASH_LENGTH;
   }

   public BigInteger toBigInteger() {
      return new BigInteger(1, bytes);
   }

   public boolean startsWith(byte[] checksum) {
      Preconditions.checkArgument(checksum.length < HASH_LENGTH); // typcially 4
      for (int i = 0, checksumLength = checksum.length; i < checksumLength; i++) {
         if (bytes[i] != checksum[i]) {
            return false;
         }
      }
      return true;
   }

   public byte[] firstFourBytes() {
      byte[] ret = new byte[4];
      System.arraycopy(bytes, 0, ret, 0, 4);
      return ret;
   }

   public byte[] firstNBytes(int n) {
      byte[] ret = new byte[n];
      System.arraycopy(bytes, 0, ret, 0, n);
      return ret;
   }

   public String toHex() {
      return HexUtils.toHex(bytes);
   }

}
