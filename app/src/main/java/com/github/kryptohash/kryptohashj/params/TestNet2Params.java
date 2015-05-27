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

package com.github.kryptohash.kryptohashj.params;

import com.github.kryptohash.kryptohashj.core.NetworkParameters;
import com.github.kryptohash.kryptohashj.core.Utils;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the old version 2 testnet. This is not useful to you - it exists only because some unit tests are
 * based on it.
 */
public class TestNet2Params extends NetworkParameters {
    public TestNet2Params() {
        super();
        id = ID_TESTNET;
        packetMagic = 0xf1fbb5adL;
        region = 0;
        hashCoin = 0;
        port = 39432;
        addressHeader = 107;
        p2shHeader = 196;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        interval = 10;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x280fffffL);
        dumpedPrivateKeyHeader = 239;
        genesisBlock.setTxTime(0x149ABA04E20L);
        genesisBlock.setDifficultyTarget(0x2600ffffL);
        genesisBlock.setNonce(0x37aab9L);
        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 210000;
        String genesisHash = genesisBlock.getHashAsString();
// TODO:       checkState(genesisHash.equals("00000051e60392d4dceb99c06a62fd23ebe1981d51854de5614050eae39abebacb770bddec466b94"));
        dnsSeeds = null;
    }

    private static TestNet2Params instance;
    public static synchronized TestNet2Params get() {
        if (instance == null) {
            instance = new TestNet2Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return null;
    }
}
