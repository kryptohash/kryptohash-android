package com.github.aelstad.keccakj.kryptohash.config;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import com.github.aelstad.keccakj.kryptohash.util.AsymmetricKeyInfoConverter;

public interface ConfigurableProvider
{
    /**
     * Diffie-Hellman Default Parameters - thread local version
     */
    static final String THREAD_LOCAL_DH_DEFAULT_PARAMS = "threadLocalDhDefaultParams";

    /**
     * Diffie-Hellman Default Parameters - VM wide version
     */
    static final String DH_DEFAULT_PARAMS = "DhDefaultParams";

    void setParameter(String parameterName, Object parameter);

    void addAlgorithm(String key, String value);

    boolean hasAlgorithm(String type, String name);

    void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter);
}