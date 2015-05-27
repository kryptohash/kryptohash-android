package com.github.aelstad.keccakj.kryptohash.config;

import javax.crypto.spec.DHParameterSpec;

public interface ProviderConfiguration
{
    DHParameterSpec getDHDefaultParameters(int keySize);
}