/**
 * Copyright 2014 Kosta Korenkov
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
package com.github.kryptohash.kryptohashj.testing;

import com.github.kryptohash.kryptohashj.core.Sha3_256Hash;
import com.github.kryptohash.kryptohashj.crypto.ChildNumber;
import com.github.kryptohash.kryptohashj.crypto.DeterministicEd25519Key;
import com.github.kryptohash.kryptohashj.signers.CustomTransactionSigner;
import com.github.kryptohash.kryptohashj.wallet.DeterministicKeyChain;
import com.google.common.collect.ImmutableList;

import java.util.List;

/**
 * <p>Transaction signer which uses provided keychain to get signing keys from. It relies on previous signer to provide
 * derivation path to be used to get signing key and, once gets the key, just signs given transaction immediately.</p>
 * It should not be used in test scenarios involving serialization as it doesn't have proper serialize/deserialize
 * implementation.
 */
public class KeyChainTransactionSigner extends CustomTransactionSigner {

    private DeterministicKeyChain keyChain;

    public KeyChainTransactionSigner() {
    }

    public KeyChainTransactionSigner(DeterministicKeyChain keyChain) {
        this.keyChain = keyChain;
    }

    @Override
    protected SignatureAndKey getSignature(Sha3_256Hash sighash, List<ChildNumber> derivationPath) {
        ImmutableList<ChildNumber> keyPath = ImmutableList.copyOf(derivationPath);
        DeterministicEd25519Key key = keyChain.getKeyByPath(keyPath, true);
        return new SignatureAndKey(key.sign(sighash), key.getPubOnly());
    }
}
