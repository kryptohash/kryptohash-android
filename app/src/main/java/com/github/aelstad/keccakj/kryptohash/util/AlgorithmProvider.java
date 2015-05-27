package com.github.aelstad.keccakj.kryptohash.util;

import com.github.aelstad.keccakj.kryptohash.config.ConfigurableProvider;

public abstract class AlgorithmProvider
{
    public abstract void configure(ConfigurableProvider provider);
}