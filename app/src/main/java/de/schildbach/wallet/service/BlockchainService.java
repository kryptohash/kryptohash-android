/*
 * Copyright 2012-2014 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.schildbach.wallet.service;

import java.util.List;

import javax.annotation.CheckForNull;

import com.github.kryptohash.kryptohashj.core.Peer;
import com.github.kryptohash.kryptohashj.core.StoredBlock;

import de.schildbach.wallet.BuildConfig;

/**
 * @author Andreas Schildbach
 */
public interface BlockchainService
{
	public static final String ACTION_PEER_STATE = BuildConfig.APPLICATION_ID + ".peer_state";
	public static final String ACTION_PEER_STATE_NUM_PEERS = "num_peers";

	public static final String ACTION_BLOCKCHAIN_STATE = BuildConfig.APPLICATION_ID + ".blockchain_state";

	public static final String ACTION_CANCEL_COINS_RECEIVED = BuildConfig.APPLICATION_ID + ".cancel_coins_received";
	public static final String ACTION_RESET_BLOCKCHAIN = BuildConfig.APPLICATION_ID + ".reset_blockchain";
	public static final String ACTION_BROADCAST_TRANSACTION = BuildConfig.APPLICATION_ID + ".broadcast_transaction";
	public static final String ACTION_BROADCAST_TRANSACTION_HASH = "hash";

	BlockchainState getBlockchainState();

	@CheckForNull
	List<Peer> getConnectedPeers();

	List<StoredBlock> getRecentBlocks(int maxBlocks);
}
