/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
 * Parameters for the testnet, a separate public instance of Kryptohash network that has relaxed rules suitable for development
 * and testing of applications and new Kryptohash versions.
 */
public class TestNet3Params extends NetworkParameters {
    public TestNet3Params() {
        super();
        id = ID_TESTNET;
        // Genesis hash is 000000071bfa8530efddbf308a70ba52f06402ab2223c95a6fdd21fe64b25128db9eb171d04f4db0
        packetMagic = 0xf1110907L;
        region = 0;
        sideChain = 0;
        interval = 10;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x2600FFFFL);
        port = 39432;
        addressHeader = 107;
        p2shHeader = 196;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        dumpedPrivateKeyHeader = 239;
        genesisBlock.setTxTime(0x149ABA02710L);
        genesisBlock.setnTime(300000);
        genesisBlock.setDifficultyTarget(0x2600FFFFL);
        genesisBlock.setNonce(0x221fbd1);
        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 125000;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000071bfa8530efddbf308a70ba52f06402ab2223c95a6fdd21fe64b25128db9eb171d04f4db0"));
        alertSigningKey = SATOSHI_KEY;

        dnsSeeds = new String[] {
                "testnet.kryptohash.org"
        };
    }

    private static TestNet3Params instance;
    public static synchronized TestNet3Params get() {
        if (instance == null) {
            instance = new TestNet3Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_TESTNET;
    }
}
