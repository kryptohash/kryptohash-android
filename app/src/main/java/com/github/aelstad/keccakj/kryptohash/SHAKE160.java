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
package com.github.aelstad.keccakj.kryptohash;

import com.github.aelstad.keccakj.core.AbstractKeccakMessageDigest;

public class SHAKE160 extends AbstractKeccakMessageDigest {
	private final static byte DOMAIN_PADDING = 0xf;
	private final static int DOMMAIN_PADDING_LENGTH = 4;
	
	public SHAKE160() {
		super("SHAKE160", 2*160, 160/8, DOMAIN_PADDING, DOMMAIN_PADDING_LENGTH);
	}

}
