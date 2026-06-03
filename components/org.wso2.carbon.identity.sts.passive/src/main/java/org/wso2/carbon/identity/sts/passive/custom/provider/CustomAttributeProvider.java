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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.sts.claims.ClaimsUtils;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.IdentityClaimManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.claim.Claim;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A custom AttributeStatementProvider implementation to be used in the implementation.
 */
public class CustomAttributeProvider implements AttributeStatementProvider {

    private static final Log log = LogFactory.getLog(CustomAttributeProvider.class);
    protected Map<String, Claim> supportedClaims = new HashMap<>();

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

        loadSupportedClaims(getCurrentTenantDomain());

        // Handle Claims.
        ProcessedClaimCollection retrievedClaims = ClaimsUtils.processClaims(providerParameters);

        AttributeStatementBean attrBean = new AttributeStatementBean();
        for (ProcessedClaim claim : retrievedClaims) {
            AttributeBean attributeBean = createAttributeFromClaim(claim, tokenType);
            attributeList.add(attributeBean);
        }
        attrBean.setSamlAttributes(attributeList);

        return attrBean;
    }

    /**
     * Returns the tenant domain of the current thread's carbon context.
     * Extracted as a protected method to allow overriding in tests.
     *
     * @return tenant domain string.
     */
    protected String getCurrentTenantDomain() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
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
            attributeBean.setNameFormat(claim.getClaimType());
        }
        String attributeNamespace = claim.getClaimType();
        String attributeName;
        if (Boolean.parseBoolean(IdentityUtil.getProperty(
                IdentityConstants.STS.PASSIVE_STS_ENABLE_CLAIM_DESCRIPTION_IN_ATTRIBUTE_NAME))
                && supportedClaims.get(attributeNamespace) != null) {
            attributeName = supportedClaims.get(attributeNamespace).getDisplayTag();
        } else {
            attributeName = createAttributeName(attributeNamespace);
            attributeNamespace = setAttributeNamespace(attributeNamespace);
        }
        attributeBean.setSimpleName(attributeName);
        attributeBean.setQualifiedName(attributeNamespace);
        attributeBean.setAttributeValues(claim.getValues());
        return attributeBean;
    }

    private String setAttributeNamespace(String attributeNamespace) {

        if (StringUtils.isNotBlank(attributeNamespace) && attributeNamespace.contains("/") &&
                attributeNamespace.length() > attributeNamespace.lastIndexOf("/") + 1) {
            return attributeNamespace.substring(0, attributeNamespace.lastIndexOf("/"));
        }
        return attributeNamespace;
    }

    private String createAttributeName(String attributeNamespace) {

        if (StringUtils.isNotBlank(attributeNamespace) && attributeNamespace.contains("/") &&
                attributeNamespace.length() > attributeNamespace.lastIndexOf("/") + 1) {
            return attributeNamespace.substring(attributeNamespace.lastIndexOf("/") + 1);
        }
        return attributeNamespace;
    }

    private void loadSupportedClaims(String spTenantDomain) {

        IdentityClaimManager claimManager;
        Claim[] claims;

        if (log.isDebugEnabled()) {
            log.debug("Loading claims");
        }

        try {
            claimManager = IdentityClaimManager.getInstance();
            claims = claimManager.getAllSupportedClaims(UserCoreConstants.DEFAULT_CARBON_DIALECT,
                    IdentityTenantUtil.getRealm(spTenantDomain, null));
            for (Claim claim : claims) {
                supportedClaims.put(claim.getClaimUri(), claim);
            }
        } catch (IdentityException e) {
            log.error("Error while loading claims", e);
        }
    }
}
