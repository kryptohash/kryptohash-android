/**
 * Copyright 2011 Google Inc.
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

package com.github.kryptohash.kryptohashj.core;

import com.github.kryptohash.kryptohashj.params.*;
import com.github.kryptohash.kryptohashj.script.Script;
import com.github.kryptohash.kryptohashj.script.ScriptOpCodes;
import com.google.common.base.Objects;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.*;

import static com.github.kryptohash.kryptohashj.core.Coin.*;

/**
 * <p>NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.</p>
 *
 * <p>This is an abstract class, concrete instantiations can be found in the params package. There are four:
 * one for the main network ({@link MainNetParams}), one for the public test network, and two others that are
 * intended for unit testing and local app development purposes. Although this class contains some aliases for
 * them, you are encouraged to call the static get() methods on each specific params class directly.</p>
 */
public abstract class NetworkParameters implements Serializable {
    /**
     * The protocol version this library implements.
     */
    public static final int PROTOCOL_VERSION = 70003;

    /**
     * The alert signing key.
     */
    public static final byte[] SATOSHI_KEY = Utils.HEX.decode("027c8d760afb55f6b999afe2cc8f659d63bb5fbd118750fe369d485b2f4c74d8a2");

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_MAINNET = "org.kryptohash.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_TESTNET = "org.kryptohash.test";
    /** The string returned by getId() for regtest mode. */
    public static final String ID_REGTEST = "org.kryptohash.regtest";
    /** Unit test network. */
    public static final String ID_UNITTESTNET = "com.github.kryptohash.kryptohashj.unittest";

    /** The string used by the payment protocol to represent the main net. */
    public static final String PAYMENT_PROTOCOL_ID_MAINNET = "main";
    /** The string used by the payment protocol to represent the test net. */
    public static final String PAYMENT_PROTOCOL_ID_TESTNET = "test";

    // TODO: Seed nodes should be here as well.

    protected Block genesisBlock;
    protected BigInteger maxTarget;
    protected int port;
    protected long packetMagic;  // Indicates message origin network and is used to seek to the next message when stream state is unknown.
    protected int region;
    protected long sideChain;
    protected int addressHeader;
    protected int p2shHeader;
    protected int dumpedPrivateKeyHeader;
    protected int interval;
    protected int targetTimespan;
    protected byte[] alertSigningKey;

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    protected String id;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    protected int spendableCoinbaseDepth;
    protected int subsidyDecreaseBlockCount;
    
    protected int[] acceptableAddressCodes;
    protected String[] dnsSeeds;
    protected Map<Integer, Shake320Hash> checkpoints = new HashMap<Integer, Shake320Hash>();

    protected NetworkParameters() {
        alertSigningKey = SATOSHI_KEY;
        genesisBlock = createGenesis(this);
    }

    private static Block createGenesis(NetworkParameters n) {
        Block genesisBlock = new Block(n);
        Transaction t = new Transaction(n);
        t.setTxTime(0x149aba00000L);
        try {
            // A script containing the difficulty bits and the following message:
            //
            // "The Guardian 11/13/2014: Comet 67P becomes landing site for Philae in historic touchdown"
            byte[] bytes = Utils.HEX.decode("04ffff002601044c5854686520477561726469616e2031312f31332f323031343a20436f6d657420363750206265636f6d6573206c616e64696e67207369746520666f72205068696c616520696e20686973746f72696320746f756368646f776e");
            t.addInput(new TransactionInput(n, bytes, t));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Utils.HEX.decode("020dc9a10284fda30c3749c308390be2b0e2df56be836d136d37679f63b258ec13"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, COIN, scriptPubKeyBytes.toByteArray()));
        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        genesisBlock.addGenesis(t);
        return genesisBlock;
    }

    public static final int TARGET_TIMESPAN = 20 * 60;  // 20 minutes per difficulty cycle, on average.
    public static final int TARGET_SPACING = 3 * 60;  // 3 minutes per block.
    public static final int INTERVAL = 100;
    
    /**
     * Blocks with a timestamp after this should enforce BIP 16, aka "Pay to script hash". This BIP changed the
     * network rules in a soft-forking manner, that is, blocks that don't follow the rules are accepted but not
     * mined upon and thus will be quickly re-orged out as long as the majority are enforcing the rule.
     */
    public static final int BIP16_ENFORCE_TIME = 1415923600;
    
    /**
     * The maximum number of coins to be generated
     */
    public static final long MAX_COINS = 10000000000000L;

    /**
     * The maximum money to be generated
     */
    public static final Coin MAX_MONEY = COIN.multiply(MAX_COINS);

    /** Alias for TestNet3Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet() {
        return TestNet3Params.get();
    }

    /** Alias for TestNet2Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet2() {
        return TestNet2Params.get();
    }

    /** Alias for TestNet3Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet3() {
        return TestNet3Params.get();
    }

    /** Alias for MainNetParams.get(), use that instead */
    @Deprecated
    public static NetworkParameters prodNet() {
        return MainNetParams.get();
    }

    /** Returns a testnet params modified to allow any difficulty target. */
    @Deprecated
    public static NetworkParameters unitTests() {
        return UnitTestParams.get();
    }

    /** Returns a standard regression test params (similar to unitTests) */
    @Deprecated
    public static NetworkParameters regTests() {
        return RegTestParams.get();
    }

    /**
     * A Java package style string acting as unique ID for these parameters
     */
    public String getId() {
        return id;
    }

    public abstract String getPaymentProtocolId();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkParameters other = (NetworkParameters) o;
        return getId().equals(other.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getId());
    }

    /** Returns the network parameters for the given string ID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromID(String id) {
        if (id.equals(ID_MAINNET)) {
            return MainNetParams.get();
        } else if (id.equals(ID_TESTNET)) {
            return TestNet3Params.get();
        } else if (id.equals(ID_UNITTESTNET)) {
            return UnitTestParams.get();
        } else if (id.equals(ID_REGTEST)) {
            return RegTestParams.get();
        } else {
            return null;
        }
    }

    /** Returns the network parameters for the given string paymentProtocolID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromPmtProtocolID(String pmtProtocolId) {
        if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_MAINNET)) {
            return MainNetParams.get();
        } else if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_TESTNET)) {
            return TestNet3Params.get();
        } else {
            return null;
        }
    }

    public int getSpendableCoinbaseDepth() {
        return spendableCoinbaseDepth;
    }

    /**
     * Returns true if the block height is either not a checkpoint, or is a checkpoint and the hash matches.
     */
    public boolean passesCheckpoint(int height, Shake320Hash hash) {
        Shake320Hash checkpointHash = checkpoints.get(height);
        return checkpointHash == null || checkpointHash.equals(hash);
    }

    /**
     * Returns true if the given height has a recorded checkpoint.
     */
    public boolean isCheckpoint(int height) {
        Shake320Hash checkpointHash = checkpoints.get(height);
        return checkpointHash != null;
    }

    public int getSubsidyDecreaseBlockCount() {
        return subsidyDecreaseBlockCount;
    }

    /** Returns DNS names that when resolved, give IP addresses of active peers. */
    public String[] getDnsSeeds() {
        return dnsSeeds;
    }

    /**
     * <p>Genesis block for this chain.</p>
     *
     * <p>The first block in every chain is a well known constant shared between all Bitcoin implemenetations. For a
     * block to be valid, it must be eventually possible to work backwards to the genesis block by following the
     * prevBlockHash pointers in the block headers.</p>
     *
     * <p>The genesis blocks for both test and prod networks contain the timestamp of when they were created,
     * and a message in the coinbase transaction. It says, <i>"The Times 03/Jan/2009 Chancellor on brink of second
     * bailout for banks"</i>.</p>
     */
    public Block getGenesisBlock() {
        return genesisBlock;
    }

    /** Default TCP port on which to connect to nodes. */
    public int getPort() {
        return port;
    }

    /** The header bytes that identify the start of a packet on this network. */
    public long getPacketMagic() {
        return packetMagic;
    }

    /** The region code for this coin */
    public int getRegion() {
        return region;
    }

    /** The sideChain for this Wallet */
    public long getSideChain() {
        return sideChain;
    }

    /**
     * First byte of a base58 encoded address. See {@link com.github.kryptohash.kryptohashj.core.Address}. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     */
    public int getAddressHeader() {
        return addressHeader;
    }

    /**
     * First byte of a base58 encoded P2SH address.  P2SH addresses are defined as part of BIP0013.
     */
    public int getP2SHHeader() {
        return p2shHeader;
    }

    /** First byte of a base58 encoded dumped private key. See {@link com.github.kryptohash.kryptohashj.core.DumpedPrivateKey}. */
    public int getDumpedPrivateKeyHeader() {
        return dumpedPrivateKeyHeader;
    }

    /**
     * How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
     * significantly different from this value, the network difficulty formula will produce a different value. Both
     * test and production Bitcoin networks use 2 weeks (1209600 seconds).
     */
    public int getTargetTimespan() {
        return targetTimespan;
    }

    /**
     * The version codes that prefix addresses which are acceptable on this network. Although Satoshi intended these to
     * be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the
     * address and to prevent accidentally sending coins across chains which would destroy them.
     */
    public int[] getAcceptableAddressCodes() {
        return acceptableAddressCodes;
    }

    /**
     * If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks.
     */
    public boolean allowEmptyPeerChain() {
        return true;
    }

    /** How many blocks pass between difficulty adjustment periods. Bitcoin standardises this to be 2015. */
    public int getInterval() {
        return interval;
    }

    /** Maximum target represents the easiest allowable proof of work. */
    public BigInteger getMaxTarget() {
        return maxTarget;
    }

    /**
     * The key used to sign {@link com.github.kryptohash.kryptohashj.core.AlertMessage}s. You can use {@link com.github.kryptohash.kryptohashj.core.Ed25519Key#verify(byte[], byte[], byte[])} to verify
     * signatures using it.
     */
    public byte[] getAlertSigningKey() {
        return alertSigningKey;
    }
}
