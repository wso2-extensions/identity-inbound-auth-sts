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

import org.apache.cxf.sts.claims.ClaimsUtils;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * A custom AttributeStatementProvider implementation to be used in the implementation.
 */
public class CustomAttributeProvider implements AttributeStatementProvider {

    /**
     * Get an AttributeStatementBean using the given parameters.
     *
     * @param providerParameters The provided parameters.
     * @return AttributeStatementBean containing the attribute list.
     */
    public AttributeStatementBean getStatement(TokenProviderParameters providerParameters) {
        List<AttributeBean> attributeList = new ArrayList<>();

        TokenRequirements tokenRequirements = providerParameters.getTokenRequirements();
        String tokenType = tokenRequirements.getTokenType();

        // Handle Claims
        ProcessedClaimCollection retrievedClaims = ClaimsUtils.processClaims(providerParameters);

        AttributeStatementBean attrBean = new AttributeStatementBean();
        Iterator<ProcessedClaim> claimIterator = retrievedClaims.iterator();
        if (!claimIterator.hasNext()) {
            // If no Claims have been processed then create a default attribute
            AttributeBean attributeBean = createDefaultAttribute(tokenType);
            attributeList.add(attributeBean);
        }

        while (claimIterator.hasNext()) {
            ProcessedClaim claim = claimIterator.next();
            AttributeBean attributeBean = createAttributeFromClaim(claim, tokenType);
            attributeList.add(attributeBean);
        }

        attrBean.setSamlAttributes(attributeList);

        return attrBean;
    }

    /**
     * Create a default attribute.
     *
     * @param tokenType Type of the token SAML1.1/SAML2.0.
     * @return Attribute bean containing the default attribute.
     */
    private AttributeBean createDefaultAttribute(String tokenType) {
        AttributeBean attributeBean = new AttributeBean();

        if (WSS4JConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType)
                || WSS4JConstants.SAML2_NS.equals(tokenType)) {
            attributeBean.setQualifiedName("http://wso2.org/claims/username");
            attributeBean.setNameFormat("http://wso2.org/claims/username");
        } else {
            attributeBean.setSimpleName("username");
            attributeBean.setQualifiedName("http://wso2.org/claims/username");
        }

        attributeBean.addAttributeValue("admin");

        return attributeBean;
    }

    /**
     * Create an Attribute from a claim.
     *
     * @param claim     The processed claim.
     * @param tokenType Type of the token SAML1.1/SAML2.0.
     * @return Attribute bean created with the help of the claim.
     */
    private AttributeBean createAttributeFromClaim(ProcessedClaim claim, String tokenType) {
        AttributeBean attributeBean = new AttributeBean();
        if (WSS4JConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType)
                || WSS4JConstants.SAML2_NS.equals(tokenType)) {
            attributeBean.setQualifiedName(claim.getClaimType());
        } else {
            attributeBean.setSimpleName(claim.getClaimType());
        }
        attributeBean.setAttributeValues(claim.getValues());

        return attributeBean;
    }

}
