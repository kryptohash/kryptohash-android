package com.github.kryptohash.kryptohashj.jni;

import com.github.kryptohash.kryptohashj.core.*;
import com.github.kryptohash.kryptohashj.protocols.channels.PaymentChannelCloseException;
import com.github.kryptohash.kryptohashj.protocols.channels.ServerConnectionEventHandler;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;

/**
 * An event listener that relays events to a native C++ object. A pointer to that object is stored in
 * this class using JNI on the native side, thus several instances of this can point to different actual
 * native implementations.
 */
public class NativePaymentChannelServerConnectionEventHandler extends ServerConnectionEventHandler {
    public long ptr;

    @Override
    public native void channelOpen(Shake320Hash channelId);

    @Override
    public native ListenableFuture<ByteString> paymentIncrease(Coin by, Coin to, ByteString info);

    @Override
    public native void channelClosed(PaymentChannelCloseException.CloseReason reason);
}
