/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.sts.passive.custom.provider;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;

public class CustomCryptoProvider extends Merlin {

    private static final Log log = LogFactory.getLog(CustomCryptoProvider.class);

    // Custom parameters which are used to get properties for the keystore in tenant mode.
    private static final String TENANT_ID_PROP = "org.apache.wss4j.crypto.merlin.keystore.tenant.id";
    private static final String KEY_STORE_NAME_PROP = "org.apache.wss4j.crypto.merlin.keystore.name";

    // Initialize the org.apache.xml.security library.
    static {
        org.apache.xml.security.Init.init();
    }

    public CustomCryptoProvider() {

    }

    public CustomCryptoProvider(boolean loadCACerts, String cacertsPasswd) {

        super(loadCACerts, cacertsPasswd);
    }

    public CustomCryptoProvider(Properties properties, ClassLoader loader,
                                PasswordEncryptor passwordEncryptor)
            throws WSSecurityException, IOException {

        super(properties, loader, passwordEncryptor);
    }

    /**
     * Loads the keystore from an InputStream or from the KeyStoreManager if it is a tenant.
     *
     * @param input     InputStream which the key store should be read from.
     * @param storepass Password of the key store.
     * @param provider  The key store provider.
     * @param type      Type of the key store.
     * @return keyStore The loaded key store.
     * @throws WSSecurityException If there is an error while loading the key store.
     */
    protected KeyStore load(InputStream input, String storepass, String provider, String type)
            throws WSSecurityException {

        KeyStore keyStore;

        String tenantId = this.properties.getProperty(TENANT_ID_PROP);
        String keyStoreName = this.properties.getProperty(KEY_STORE_NAME_PROP);

        log.debug("Loading keystore...");
        if (!String.valueOf(MultitenantConstants.SUPER_TENANT_ID).equals(tenantId)
                && keyStoreName != null) {
            // Loads the keystore in a custom way since the tenant keystore does not have a location.
            if (log.isDebugEnabled()) {
                log.debug("Loading keystore for tenant with id: " + tenantId + ".");
            }
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(Integer.parseInt(tenantId));
            try {
                keyStore = keyStoreManager.getKeyStore(keyStoreName);
            } catch (Exception exception) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, exception, "failedCredentialLoad");
            }
        } else {
            // Loads the keystore in the default way since the keystore has a location.
            if (log.isDebugEnabled()) {
                log.debug("Loading keystore for super tenant.");
            }
            keyStore = super.load(input, storepass, provider, type);
        }
        return keyStore;
    }
}
