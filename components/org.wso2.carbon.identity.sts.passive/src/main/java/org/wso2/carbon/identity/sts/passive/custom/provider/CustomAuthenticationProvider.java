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

import org.apache.cxf.sts.token.provider.AuthenticationStatementProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.saml.bean.AuthenticationStatementBean;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;

/**
 * A custom AuthenticationStatementProvider implementation to be used in the implementation.
 */
public class CustomAuthenticationProvider implements AuthenticationStatementProvider {

    /**
     * Get an AuthenticationStatementBean using the given parameters.
     *
     * @param providerParameters Provided token provider params.
     * @return An authentication statement bean.
     */
    public AuthenticationStatementBean getStatement(TokenProviderParameters providerParameters) {
        AuthenticationStatementBean authBean = new AuthenticationStatementBean();

        // Check for SAML Token type and set the authentication method.
        if (WSS4JConstants.WSS_SAML_TOKEN_TYPE.equals(
                providerParameters.getTokenRequirements().getTokenType())) {
            authBean.setAuthenticationMethod(SAML1Constants.AUTH_METHOD_PASSWORD);
        } else {
            authBean.setAuthenticationMethod(SAML2Constants.AUTH_CONTEXT_CLASS_REF_PASSWORD);
        }
        return authBean;
    }

}
