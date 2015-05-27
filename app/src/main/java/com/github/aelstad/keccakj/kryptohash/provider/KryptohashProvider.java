/*
 * Copyright 2015 Oscar A. Perez
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.aelstad.keccakj.kryptohash.provider;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import com.github.aelstad.keccakj.kryptohash.util.AlgorithmProvider;
import com.github.aelstad.keccakj.kryptohash.util.AsymmetricKeyInfoConverter;
import com.github.aelstad.keccakj.kryptohash.config.ConfigurableProvider;
import com.github.aelstad.keccakj.kryptohash.config.ProviderConfiguration;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;

public final class KryptohashProvider extends Provider implements ConfigurableProvider {

	private static String info = "Kryptohash Security Provider v1.0";
	public static final String PROVIDER_NAME = "KHC";
	private static final Map keyInfoConverters = new HashMap();
	public static final ProviderConfiguration CONFIGURATION = new KHCProviderConfiguration();

	/*
     * Configurable digests
     */
	private static final String DIGEST_PACKAGE = "com.github.aelstad.keccakj.kryptohash.";
	private static final String[] DIGESTS =
	{
			"SHA3-224", "SHA3-256", "SHAKE160", "SHAKE320"
	};

	public KryptohashProvider() {
		super(PROVIDER_NAME, 1.0, info);

		AccessController.doPrivileged(new PrivilegedAction() {
			public Object run() {
				setup();
				return null;
			}
		});
	}

	private void setup() {
		loadAlgorithms(DIGEST_PACKAGE, DIGESTS);
	}

	private void loadAlgorithms(String packageName, String[] names)
	{
		for (int i = 0; i != names.length; i++)
		{
			Class clazz = null;
			try
			{
				ClassLoader loader = this.getClass().getClassLoader();

				if (loader != null)
				{
					clazz = loader.loadClass(packageName + names[i] + "$Mappings");
				}
				else
				{
					clazz = Class.forName(packageName + names[i] + "$Mappings");
				}
			}
			catch (ClassNotFoundException e)
			{
				// ignore
			}

			if (clazz != null)
			{
				try
				{
					((AlgorithmProvider)clazz.newInstance()).configure(this);
				}
				catch (Exception e)
				{   // this should never ever happen!!
					throw new InternalError("cannot create instance of "
							+ packageName + names[i] + "$Mappings : " + e);
				}
			}
		}
	}

	public void setParameter(String parameterName, Object parameter)
	{
		synchronized (CONFIGURATION)
		{
			((KHCProviderConfiguration)CONFIGURATION).setParameter(parameterName, parameter);
		}
	}

	public boolean hasAlgorithm(String type, String name)
	{
		return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
	}

	public void addAlgorithm(String key, String value)
	{
		if (containsKey(key))
		{
			throw new IllegalStateException("duplicate provider key (" + key + ") found");
		}

		put(key, value);
	}

	public void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter)
	{
		keyInfoConverters.put(oid, keyInfoConverter);
	}

	public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
			throws IOException
	{
		AsymmetricKeyInfoConverter converter = (AsymmetricKeyInfoConverter)keyInfoConverters.get(publicKeyInfo.getAlgorithm().getAlgorithm());

		if (converter == null)
		{
			return null;
		}

		return converter.generatePublic(publicKeyInfo);
	}

	public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
			throws IOException
	{
		AsymmetricKeyInfoConverter converter = (AsymmetricKeyInfoConverter)keyInfoConverters.get(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

		if (converter == null)
		{
			return null;
		}

		return converter.generatePrivate(privateKeyInfo);
	}

}
