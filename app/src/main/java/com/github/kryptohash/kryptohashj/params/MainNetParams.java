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
import com.github.kryptohash.kryptohashj.core.Shake320Hash;
import com.github.kryptohash.kryptohashj.core.Utils;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class MainNetParams extends NetworkParameters {
    public MainNetParams() {
        super();
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x2600FFFFL);
        dumpedPrivateKeyHeader = 128;
        addressHeader = 45;
        p2shHeader = 5;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        port = 39168;
        packetMagic = 0xf1ebb49dL;
        region = 0;
        sideChain = 0;
        genesisBlock.setDifficultyTarget(0x2600FFFFL);
        genesisBlock.setTxTime(0x149aba00000L);
        genesisBlock.setnTime(300000);
        genesisBlock.setNonce(0x6261b);
        id = ID_MAINNET;
        subsidyDecreaseBlockCount = 125000;
        spendableCoinbaseDepth = 100;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000aa3109c4fa8691ddf8f96fcfbbedbb8b1f3be7675b875cd1552468a58f4f8997bf6636db9f"), genesisHash);

        // This contains (at a minimum) the blocks which are not BIP30 compliant. BIP30 changed how duplicate
        // transactions are handled. Duplicated transactions could occur in the case where a coinbase had the same
        // extraNonce and the same outputs but appeared at different heights, and greatly complicated re-org handling.
        // Having these here simplifies block connection logic considerably.
        checkpoints.put(50000, new Shake320Hash("0000000474061a227e8b28d6386a576ea85a1403a6cf24a9a43a1307bdc6f0edeea5e57f7ccd75d1"));

        dnsSeeds = new String[] {
                "seed0.kryptohash.org",
                "seed1.kryptohash.org"
        };
    }

    private static MainNetParams instance;
    public static synchronized MainNetParams get() {
        if (instance == null) {
            instance = new MainNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_MAINNET;
    }
}
