/**
 * Copyright 2011 Google Inc.
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

package com.github.kryptohash.kryptohashj.store;

import com.github.kryptohash.kryptohashj.core.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Keeps {@link com.github.kryptohash.kryptohashj.core.StoredBlock}s in memory. Used primarily for unit testing.
 */
public class MemoryBlockStore implements BlockStore {
    private LinkedHashMap<Shake320Hash, StoredBlock> blockMap = new LinkedHashMap<Shake320Hash, StoredBlock>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Shake320Hash, StoredBlock> eldest) {
            return blockMap.size() > 5000;
        }
    };
    private StoredBlock chainHead;

    public MemoryBlockStore(NetworkParameters params) {
        // Insert the genesis block.
        try {
            Block genesisHeader = params.getGenesisBlock().cloneAsHeader();
            StoredBlock storedGenesis = new StoredBlock(genesisHeader, genesisHeader.getWork(), 0);
            put(storedGenesis);
            setChainHead(storedGenesis);
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Override
    public synchronized void put(StoredBlock block) throws BlockStoreException {
        if (blockMap == null) throw new BlockStoreException("MemoryBlockStore is closed");
        Shake320Hash hash = block.getHeader().getHash();
        blockMap.put(hash, block);
    }

    @Override
    public synchronized StoredBlock get(Shake320Hash hash) throws BlockStoreException {
        if (blockMap == null) throw new BlockStoreException("MemoryBlockStore is closed");
        return blockMap.get(hash);
    }

    @Override
    public StoredBlock getChainHead() throws BlockStoreException {
        if (blockMap == null) throw new BlockStoreException("MemoryBlockStore is closed");
        return chainHead;
    }

    @Override
    public void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        if (blockMap == null) throw new BlockStoreException("MemoryBlockStore is closed");
        this.chainHead = chainHead;
    }
    
    @Override
    public void close() {
        blockMap = null;
    }
}
