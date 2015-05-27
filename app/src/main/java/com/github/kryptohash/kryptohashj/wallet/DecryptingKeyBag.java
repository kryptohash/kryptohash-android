/**
 * Copyright 2014 The bitcoinj authors.
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

package com.github.kryptohash.kryptohashj.wallet;

import com.github.kryptohash.kryptohashj.core.Ed25519Key;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A DecryptingKeyBag filters a pre-existing key bag, decrypting keys as they are requested using the provided
 * AES key. If the keys are encrypted and no AES key provided, {@link com.github.kryptohash.kryptohashj.core.Ed25519Key.KeyIsEncryptedException}
 * will be thrown.
 */
public class DecryptingKeyBag implements KeyBag {
    protected final KeyBag target;
    protected final KeyParameter aesKey;

    public DecryptingKeyBag(KeyBag target, @Nullable KeyParameter aesKey) {
        this.target = checkNotNull(target);
        this.aesKey = aesKey;
    }

    @Nullable
    private Ed25519Key maybeDecrypt(Ed25519Key key) {
        if (key == null)
            return null;
        else if (key.isEncrypted()) {
            if (aesKey == null)
                throw new Ed25519Key.KeyIsEncryptedException();
            return key.decrypt(aesKey);
        } else {
            return key;
        }
    }

    private RedeemData maybeDecrypt(RedeemData redeemData) {
        List<Ed25519Key> decryptedKeys = new ArrayList<Ed25519Key>();
        for (Ed25519Key key : redeemData.keys) {
            decryptedKeys.add(maybeDecrypt(key));
        }
        return RedeemData.of(decryptedKeys, redeemData.redeemScript);
    }

    @Nullable
    @Override
    public Ed25519Key findKeyFromPubHash(byte[] pubkeyHash) {
        return maybeDecrypt(target.findKeyFromPubHash(pubkeyHash));
    }

    @Nullable
    @Override
    public Ed25519Key findKeyFromPubKey(byte[] pubkey) {
        return maybeDecrypt(target.findKeyFromPubKey(pubkey));
    }

    @Nullable
    @Override
    public RedeemData findRedeemDataFromScriptHash(byte[] scriptHash) {
        return maybeDecrypt(target.findRedeemDataFromScriptHash(scriptHash));
    }
}
