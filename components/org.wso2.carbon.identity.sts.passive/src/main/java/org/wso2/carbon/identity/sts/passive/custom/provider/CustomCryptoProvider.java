/*
 * Copyright (c) 2020-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sts.passive.custom.provider;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

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
     * Loads the keystore from identity keystore resolver.
     * Keystore will be either super tenant keystore, tenanted keystore, or custom
     * keystore configured for WS-Federation.
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

        String tenantId = this.properties.getProperty(TENANT_ID_PROP);

        if (log.isDebugEnabled()) {
            log.debug("Loading keystore for tenant with id: " + tenantId + ".");
        }
        try {
            String tenantDomain;

            if (StringUtils.isBlank(tenantId)) {
                tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            } else {
                tenantDomain = IdentityTenantUtil.getTenantDomain(Integer.parseInt(tenantId));
            }

            return IdentityKeyStoreResolver.getInstance()
                    .getKeyStore(tenantDomain, IdentityKeyStoreResolverConstants.InboundProtocol.WS_FEDERATION);
        } catch (Exception exception) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, exception, "failedCredentialLoad");
        }
    }
}
