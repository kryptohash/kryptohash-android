package com.github.aelstad.keccakj.kryptohash.provider;

import java.security.Permission;

import javax.crypto.spec.DHParameterSpec;

import com.github.aelstad.keccakj.kryptohash.config.ConfigurableProvider;
import com.github.aelstad.keccakj.kryptohash.config.ProviderConfiguration;
import com.github.aelstad.keccakj.kryptohash.config.ProviderConfigurationPermission;

class KHCProviderConfiguration implements ProviderConfiguration
{
    private static Permission BC_DH_LOCAL_PERMISSION = new ProviderConfigurationPermission(
        KryptohashProvider.PROVIDER_NAME, ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS);
    private static Permission BC_DH_PERMISSION = new ProviderConfigurationPermission(
        KryptohashProvider.PROVIDER_NAME, ConfigurableProvider.DH_DEFAULT_PARAMS);

    private ThreadLocal ecThreadSpec = new ThreadLocal();
    private ThreadLocal dhThreadSpec = new ThreadLocal();

    private volatile Object dhDefaultParams;

    void setParameter(String parameterName, Object parameter)
    {
        SecurityManager securityManager = System.getSecurityManager();

        if (parameterName.equals(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS))
        {
            Object dhSpec;

            if (securityManager != null)
            {
                securityManager.checkPermission(BC_DH_LOCAL_PERMISSION);
            }

            if (parameter instanceof DHParameterSpec || parameter instanceof DHParameterSpec[] || parameter == null)
            {
                dhSpec = parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid DHParameterSpec");
            }

            if (dhSpec == null)
            {
                dhThreadSpec.remove();
            }
            else
            {
                dhThreadSpec.set(dhSpec);
            }
        }
        else if (parameterName.equals(ConfigurableProvider.DH_DEFAULT_PARAMS))
        {
            if (securityManager != null)
            {
                securityManager.checkPermission(BC_DH_PERMISSION);
            }

            if (parameter instanceof DHParameterSpec || parameter instanceof DHParameterSpec[] || parameter == null)
            {
                dhDefaultParams = parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid DHParameterSpec or DHParameterSpec[]");
            }
        }
    }

    public DHParameterSpec getDHDefaultParameters(int keySize)
    {
        Object params = dhThreadSpec.get();
        if (params == null)
        {
            params = dhDefaultParams;
        }

        if (params instanceof DHParameterSpec)
        {
            DHParameterSpec spec = (DHParameterSpec)params;

            if (spec.getP().bitLength() == keySize)
            {
                return spec;
            }
        }
        else if (params instanceof DHParameterSpec[])
        {
            DHParameterSpec[] specs = (DHParameterSpec[])params;

            for (int i = 0; i != specs.length; i++)
            {
                if (specs[i].getP().bitLength() == keySize)
                {
                    return specs[i];
                }
            }
        }

        return null;
    }
}