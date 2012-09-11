/**
 * Copyright 2012 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.keyczardemo;

import java.security.Provider;
import java.security.Security;

import org.spongycastle.jcajce.provider.symmetric.AES;

import android.os.Build;

/**
 * Fixes a problem in the CipherSpi provided in Android before Ice Cream
 * Sandwich. Whenever {@code null} is returned from {@code engineUpdate()} using
 * the {@code ByteBuffer} interface, it would cause a NullPointerException.
 */
public class FixBrokenCipherSpiProvider extends Provider {
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    private static class Holder {
        private static FixBrokenCipherSpiProvider INSTANCE = new FixBrokenCipherSpiProvider();
    }

    public static void insertIfNeeded() {
        Holder.INSTANCE.poke();
    }

    private void poke() {
    }

    public FixBrokenCipherSpiProvider() {
        super("FixBrokenCipherSpiProvider", 1.0, "Workaround for bug in pre-ICS Harmony");

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            put("Cipher.AES", FixBrokenCipherSpiAESECB.class.getName());
            Security.insertProviderAt(this, 1);
        }
    }

    public static class FixBrokenCipherSpiAESECB extends AES.ECB {
        @Override
        protected byte[] engineUpdate(byte[] input, int offset, int len) {
            final byte[] result = super.engineUpdate(input, offset, len);
            return result == null ? EMPTY_BYTE_ARRAY : result;
        }
    }
}
