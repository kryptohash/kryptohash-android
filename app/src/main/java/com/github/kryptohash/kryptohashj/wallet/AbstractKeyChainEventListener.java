package com.github.kryptohash.kryptohashj.wallet;

import com.github.kryptohash.kryptohashj.core.Ed25519Key;

import java.util.List;

public class AbstractKeyChainEventListener implements KeyChainEventListener {
    @Override
    public void onKeysAdded(List<Ed25519Key> keys) {
    }
}
