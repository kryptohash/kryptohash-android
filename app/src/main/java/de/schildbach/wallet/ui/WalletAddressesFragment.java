/*
 * Copyright 2011-2014 the original author or authors.
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

package de.schildbach.wallet.ui;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.annotation.Nonnull;

import com.github.kryptohash.kryptohashj.core.AbstractWalletEventListener;
import com.github.kryptohash.kryptohashj.core.Address;
import com.github.kryptohash.kryptohashj.core.Ed25519Key;
import com.github.kryptohash.kryptohashj.core.Wallet;
import com.github.kryptohash.kryptohashj.core.WalletEventListener;
import com.github.kryptohash.kryptohashj.uri.BitcoinURI;
import com.github.kryptohash.kryptohashj.utils.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.support.v7.view.ActionMode;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.BaseAdapter;
import android.widget.ListAdapter;
import android.widget.ListView;
import de.schildbach.wallet.AddressBookProvider;
import de.schildbach.wallet.BuildConfig;
import de.schildbach.wallet.Constants;
import de.schildbach.wallet.WalletApplication;
import de.schildbach.wallet.util.BitmapFragment;
import de.schildbach.wallet.util.Qr;
import de.schildbach.wallet.util.WalletUtils;
import de.schildbach.wallet.util.WholeStringBuilder;
import de.schildbach.wallet.R;

/**
 * @author Andreas Schildbach
 */
public final class WalletAddressesFragment extends FancyListFragment
{
	private AddressBookActivity activity;
	private WalletApplication application;
	private Wallet wallet;
	private ClipboardManager clipboardManager;
	private ContentResolver contentResolver;

	private WalletAddressesAdapter adapter;

	private static final Logger log = LoggerFactory.getLogger(WalletAddressesFragment.class);

	@Override
	public void onAttach(final Activity activity)
	{
		super.onAttach(activity);

		this.activity = (AddressBookActivity) activity;
		this.application = (WalletApplication) activity.getApplication();
		this.wallet = application.getWallet();
		this.clipboardManager = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
		this.contentResolver = activity.getContentResolver();
	}

	@Override
	public void onCreate(final Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		setHasOptionsMenu(true);

		adapter = new WalletAddressesAdapter(activity, wallet);

		setListAdapter(adapter);
	}

	@Override
	public void onViewCreated(final View view, final Bundle savedInstanceState)
	{
		super.onViewCreated(view, savedInstanceState);

		setEmptyText(WholeStringBuilder.bold(getString(R.string.address_book_empty_text)));
	}

	@Override
	public void onResume()
	{
		super.onResume();

		contentResolver.registerContentObserver(AddressBookProvider.contentUri(BuildConfig.APPLICATION_ID), true, contentObserver);

		wallet.addEventListener(walletListener, Threading.SAME_THREAD);
		walletListener.onKeysAdded(null); // trigger initial load of keys

		updateView();
	}

	@Override
	public void onPause()
	{
		wallet.removeEventListener(walletListener);

		contentResolver.unregisterContentObserver(contentObserver);

		super.onPause();
	}

	@Override
	public void onCreateOptionsMenu(final Menu menu, final MenuInflater inflater)
	{
		inflater.inflate(R.menu.wallet_addresses_fragment_options, menu);

		super.onCreateOptionsMenu(menu, inflater);
	}

	@Override
	public void onListItemClick(final ListView l, final View v, final int position, final long id)
	{
		activity.startSupportActionMode(new ActionMode.Callback()
		{
			@Override
			public boolean onCreateActionMode(final ActionMode mode, final Menu menu)
			{
				final MenuInflater inflater = mode.getMenuInflater();
				inflater.inflate(R.menu.wallet_addresses_context, menu);

				return true;
			}

			@Override
			public boolean onPrepareActionMode(final ActionMode mode, final Menu menu)
			{
				final Ed25519Key key = getKey(position);

				final String address = key.toAddress(Constants.NETWORK_PARAMETERS).toString();
				final String label = AddressBookProvider.resolveLabel(activity, address);
				mode.setTitle(label != null ? label : WalletUtils.formatHash(address, Constants.ADDRESS_FORMAT_GROUP_SIZE, 0));

				return true;
			}

			@Override
			public boolean onActionItemClicked(final ActionMode mode, final MenuItem item)
			{
				switch (item.getItemId())
				{
					case R.id.wallet_addresses_context_edit:
						handleEdit(getAddress(position));

						mode.finish();
						return true;

					case R.id.wallet_addresses_context_show_qr:
						handleShowQr(getAddress(position));

						mode.finish();
						return true;

					case R.id.wallet_addresses_context_copy_to_clipboard:
						handleCopyToClipboard(getAddress(position));

						mode.finish();
						return true;

					case R.id.wallet_addresses_context_browse:
						startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(Constants.EXPLORE_BASE_URL + "address/"
								+ getAddress(position).toString())));

						mode.finish();
						return true;
				}

				return false;
			}

			@Override
			public void onDestroyActionMode(final ActionMode mode)
			{
			}

			private Ed25519Key getKey(final int position)
			{
				return (Ed25519Key) getListAdapter().getItem(position);
			}

			private Address getAddress(final int position)
			{
				return getKey(position).toAddress(Constants.NETWORK_PARAMETERS);
			}

			private void handleEdit(@Nonnull final Address address)
			{
				EditAddressBookEntryFragment.edit(getFragmentManager(), address.toString());
			}

			private void handleShowQr(@Nonnull final Address address)
			{
				final String uri = BitcoinURI.convertToBitcoinURI(address, null, null, null);
                final int size = getResources().getDimensionPixelSize(R.dimen.bitmap_dialog_qr_size);
				BitmapFragment.show(getFragmentManager(), Qr.bitmap(uri, size));
			}

			private void handleCopyToClipboard(@Nonnull final Address address)
			{
				clipboardManager.setPrimaryClip(ClipData.newPlainText("Bitcoin address", address.toString()));
				log.info("address copied to clipboard: {}", address.toString());
				activity.toast(R.string.wallet_address_fragment_clipboard_msg);
			}
		});
	}

	private void updateView()
	{
		final ListAdapter adapter = getListAdapter();
		if (adapter != null)
			((BaseAdapter) adapter).notifyDataSetChanged();
	}

	private final Handler handler = new Handler();

	private final ContentObserver contentObserver = new ContentObserver(handler)
	{
		@Override
		public void onChange(final boolean selfChange)
		{
			updateView();
		}
	};

	private final WalletEventListener walletListener = new AbstractWalletEventListener()
	{
		@Override
		public void onKeysAdded(final List<Ed25519Key> keysAdded)
		{
			final List<Ed25519Key> keys = wallet.getImportedKeys();

			Collections.sort(keys, new Comparator<Ed25519Key>()
			{
				@Override
				public int compare(final Ed25519Key lhs, final Ed25519Key rhs)
				{
					final boolean lhsRotating = wallet.isKeyRotating(lhs);
					final boolean rhsRotating = wallet.isKeyRotating(rhs);

					if (lhsRotating != rhsRotating)
						return lhsRotating ? 1 : -1;

					if (lhs.getCreationTimeSeconds() != rhs.getCreationTimeSeconds())
						return lhs.getCreationTimeSeconds() > rhs.getCreationTimeSeconds() ? 1 : -1;

					return 0;
				}
			});

			handler.post(new Runnable()
			{
				@Override
				public void run()
				{
					adapter.replace(keys);
				}
			});
		}
	};
}