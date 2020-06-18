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
package org.wso2.carbon.identity.sts.passive.custom.handler;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.sts.passive.utils.RequestProcessorUtil;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * A custom CallbackHandler implementation to be used in the implementation.
 */
public class PasswordCallbackHandler implements CallbackHandler {

    public void handle(Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {

        ServerConfiguration serverConfig = ServerConfiguration.getInstance();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();

        String[] aliasAndPassword;
        try {
            aliasAndPassword = RequestProcessorUtil
                    .getKeyStoreAliasAndKeyStorePassword(serverConfig, tenantId, tenantDomain);
        } catch (Exception exception) {
            throw new IOException(exception);
        }
        String keyAlias = aliasAndPassword[0];
        String keyStorePassword = aliasAndPassword[1];

        for (Callback callback : callbacks) {
            if (callback instanceof WSPasswordCallback) { // CXF
                WSPasswordCallback pc = (WSPasswordCallback) callback;
                if ("alice".equals(pc.getIdentifier())) {
                    pc.setPassword("clarinet");
                    break;
                } else if ("bob".equals(pc.getIdentifier())) {
                    pc.setPassword("trombone");
                    break;
                } else if (keyAlias.equals(pc.getIdentifier())) {
                    pc.setPassword(keyStorePassword);
                    break;
                } else if ("myservicekey".equals(pc.getIdentifier())) {
                    pc.setPassword("skpass");
                    break;
                }
            }
        }
    }
}
