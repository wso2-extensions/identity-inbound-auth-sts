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
package org.wso2.carbon.identity.sts.common.identity.provider;

import org.apache.axiom.om.OMElement;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.impl.util.SAMLAttributeCallback;
import org.apache.rahas.impl.util.SAMLCallback;
import org.apache.rahas.impl.util.SAMLCallbackHandler;
import org.opensaml.Configuration;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.IdentityClaimManager;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.provider.IdentityProviderException;
import org.wso2.carbon.identity.sts.common.internal.IdentityProviderSTSServiceComponent;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AUTHENTICATED_USER;
import static org.wso2.carbon.user.core.UserCoreConstants.DEFAULT_PROFILE;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

public class AttributeCallbackHandler implements SAMLCallbackHandler {

    private static final Log log = LogFactory.getLog(AttributeCallbackHandler.class);
    protected Map<String, RequestedClaimData> requestedClaims = new HashMap<>();
    protected Map<String, String> requestedClaimValues = new HashMap<>();
    protected Map<String, Claim> supportedClaims = new HashMap<>();
    private String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

    @Override
    public void handle(SAMLCallback callback) throws SAMLException {

        SAMLAttributeCallback attrCallback = null;
        RahasData data = null;
        OMElement claimElem = null;
        String claimDialect = null;
        String userIdentifier = null;
        String[] splitArr = null;
        IdentityAttributeService[] attributeCallbackServices = null;
        String endPointReference = null;
        String spTenantDomain = null;

        if (callback instanceof SAMLAttributeCallback) {
            attrCallback = (SAMLAttributeCallback) callback;
            data = attrCallback.getData();
            claimElem = data.getClaimElem();
            claimDialect = data.getClaimDialect();
            userIdentifier = data.getPrincipal().getName();
            endPointReference = data.getAppliesToAddress();
            spTenantDomain = data.getInMessageContext().getProperty("spTenantDomain") != null ?
                    (String) data.getInMessageContext().getProperty("spTenantDomain") :
                    SUPER_TENANT_DOMAIN_NAME;
            AuthenticatedUser authenticatedUser = (AuthenticatedUser) data.getInMessageContext()
                    .getProperty(AUTHENTICATED_USER);


            if (userIdentifier != null) {
                    /*Extract 'Common Name' as the user id if authenticated
                      via X.509 certificates*/
                splitArr = userIdentifier.split(",")[0].split("=");
                if (splitArr.length == 2) {
                    userIdentifier = splitArr[1];
                } else if (!userIdentifier.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
                    // if the user identifier is not qualified with user store domain, making it so.
                    userIdentifier = IdentityUtil.addDomainToName(userIdentifier,
                            UserCoreUtil.getDomainFromThreadLocal());
                }
            }

            if (StringUtils.isNotEmpty(claimDialect) && claimElem != null) {
                try {
                    processClaimData(data, claimElem);
                    loadClaims(claimElem, spTenantDomain);
                    populateClaimValues(userIdentifier, attrCallback);
                } catch (IdentityProviderException e) {
                    log.error("Error occurred while populating claim data", e);
                }

                attributeCallbackServices = IdentityAttributeServiceStore.getAttributeServices();
                for (int i = 0; i < attributeCallbackServices.length; i++) {
                    try {
                        attributeCallbackServices[i].handle(attrCallback);
                    } catch (Exception e) {
                        log.error("Error occurred while calling attribute callback", e);
                    }
                }
            } else {
                String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
                ApplicationManagementService applicationManagementService =
                        IdentityProviderSTSServiceComponent.getApplicationManagementService();
                try {
                    ServiceProvider serviceProvider =
                            applicationManagementService.getServiceProviderByClientId(endPointReference, "wstrust",
                                    tenantDomain);
                    ClaimMapping[] claimMappings = serviceProvider.getClaimConfig().getClaimMappings();

                    for (int i = 0; i < claimMappings.length; i++) {
                        String localClaimUri = claimMappings[i].getLocalClaim().getClaimUri();
                        String remoteClaimUri = claimMappings[i].getRemoteClaim().getClaimUri();

                        if (StringUtils.isNotBlank(localClaimUri) && StringUtils.isNotBlank(remoteClaimUri)) {
                            String remoteClaimSuffixValue = remoteClaimUri.substring(remoteClaimUri.lastIndexOf('/') + 1);
                            String remoteClaimPrefixValue = remoteClaimUri.substring(0, remoteClaimUri.lastIndexOf('/'));
                            String localClaimValue = null;

                            if (StringUtils.isNotBlank(remoteClaimSuffixValue) &&
                                    StringUtils.isNotBlank(remoteClaimPrefixValue)) {
                                // WS trust flow does not set the authenticated user property.
                                if (isHandlerCalledFromWSTrustSTSFlow(attrCallback)) {
                                    tenantDomain = getTenantDomainFromThreadLocalContext();
                                    UserRealm userRealm = IdentityTenantUtil.getRealm(tenantDomain, null);
                                    localClaimValue = userRealm.getUserStoreManager().getUserClaimValue(userIdentifier,
                                            localClaimUri, DEFAULT_PROFILE);
                                } else if (!authenticatedUser.isFederatedUser()) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Loading claim values from local UserStore for user: "
                                                + authenticatedUser.toString());
                                    }
                                    tenantDomain = getTenantDomainFromThreadLocalContext();
                                    UserRealm userRealm = IdentityTenantUtil.getRealm(tenantDomain, null);
                                    localClaimValue = userRealm.getUserStoreManager().getUserClaimValue(userIdentifier,
                                            localClaimUri, DEFAULT_PROFILE);
                                }

                                if (StringUtils.isEmpty(localClaimValue)) {
                                    localClaimValue = new String();
                                    if (log.isDebugEnabled()) {
                                        log.debug("Claim Values haven't properly set");
                                    }
                                }
                                SAMLAttribute attribute = new SAMLAttribute(remoteClaimSuffixValue,
                                        remoteClaimPrefixValue, null, -1, Arrays
                                        .asList(new String[]{localClaimValue}));
                                attrCallback.addAttributes(attribute);
                            }

                        }
                    }
                } catch (IdentityApplicationManagementException e) {
                    throw new SAMLException("Error while loading SP specific claims", e);
                } catch (org.wso2.carbon.user.core.UserStoreException | IdentityException e) {
                    throw new SAMLException("Error while loading claims of the user", e);
                }
            }
        }
    }

    private Attribute getSAML2Attribute(String name, String value, String namespace) {

        XMLObjectBuilderFactory builderFactory = null;
        SAMLObjectBuilder<Attribute> attrBuilder = null;
        Attribute attribute = null;
        XSStringBuilder attributeValueBuilder = null;
        XSString stringValue = null;

        builderFactory = Configuration.getBuilderFactory();
        attrBuilder = (SAMLObjectBuilder<Attribute>) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        attribute = attrBuilder.buildObject();
        attribute.setName(name);
        attribute.setNameFormat(namespace);

        attributeValueBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);
        stringValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        stringValue.setValue(value);
        attribute.getAttributeValues().add(stringValue);
        return attribute;
    }

    /**
     * This method loads claim according to the claim dialect that is defined in the request
     *
     * @param claimsElement
     * @param spTenantDomain
     * @throws IdentityProviderException
     */
    private void loadClaims(OMElement claimsElement, String spTenantDomain) throws IdentityProviderException {

        IdentityClaimManager claimManager;
        Claim[] claims;
        String claimDialect = null;

        if (claimsElement.getNamespace() != null) {
            claimDialect = claimsElement
                    .getAttributeValue(new QName(claimsElement.getNamespace().getNamespaceURI(), "Dialect"));
        }

        if (claimDialect == null || claimDialect.trim().length() == 0) {
            claimDialect = UserCoreConstants.DEFAULT_CARBON_DIALECT;
        }

        if (log.isDebugEnabled()) {
            log.debug("Loading claims");
        }

        try {
            claimManager = IdentityClaimManager.getInstance();
            claims =
                    claimManager.getAllSupportedClaims(claimDialect, IdentityTenantUtil.getRealm(spTenantDomain, null));
            for (int i = 0; i < claims.length; i++) {
                Claim temp = claims[i];
                supportedClaims.put(temp.getClaimUri(), temp);
            }
        } catch (IdentityException e) {
            log.error("Error while loading claims", e);
            throw new IdentityProviderException("Error while loading claims", e);
        }
    }

    protected void loadClaims(String userIdentifier) throws IdentityProviderException {

        IdentityClaimManager claimManager = null;
        Claim[] claims = null;

        if (log.isDebugEnabled()) {
            log.debug("Loading claims");
        }

        try {
            claimManager = IdentityClaimManager.getInstance();
            claims = claimManager.getAllSupportedClaims(UserCoreConstants.DEFAULT_CARBON_DIALECT,
                    IdentityTenantUtil.getRealm(null, userIdentifier));
            for (int i = 0; i < claims.length; i++) {
                Claim temp = claims[i];
                supportedClaims.put(temp.getClaimUri(), temp);
            }
        } catch (IdentityException e) {
            log.error("Error while loading claims", e);
            throw new IdentityProviderException("Error while loading claims", e);
        }
    }

    /**
     * @param rahasData
     * @param claims
     * @throws IdentityProviderException
     */
    protected void processClaimData(RahasData rahasData, OMElement claims) throws IdentityProviderException {

        if (claims == null) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Processing claim data");
        }

        Iterator iterator = null;
        iterator = claims.getChildrenWithName(
                new QName(IdentityConstants.NS, IdentityConstants.LocalNames.IDENTITY_CLAIM_TYPE));

        while (iterator.hasNext()) {
            OMElement omElem = null;
            RequestedClaimData claim = null;
            String uriClaim = null;
            String optional = null;

            omElem = (OMElement) iterator.next();
            claim = getRequestedClaim();
            uriClaim = omElem.getAttributeValue(new QName(null, "Uri"));

            if (uriClaim == null) {
                log.error("Empty claim uri found while procession claim data");
                throw new IdentityProviderException("Empty claim uri found while procession claim data");
            }

            if (uriClaim.startsWith("{") && uriClaim.endsWith("}")
                    && uriClaim.lastIndexOf("|") == uriClaim.indexOf("|")) {
                String tmpUri = uriClaim;
                uriClaim = uriClaim.substring(1, uriClaim.indexOf("|"));
                String claimValue = tmpUri.substring(tmpUri.indexOf("|") + 1, tmpUri.length() - 1);
                requestedClaimValues.put(uriClaim, claimValue);
            }

            claim.setUri(uriClaim);
            optional = (omElem.getAttributeValue(new QName(null, "Optional")));
            if (StringUtils.isNotBlank(optional)) {
                claim.setBOptional("true".equals(optional));
            } else {
                claim.setBOptional(true);
            }

            requestedClaims.put(claim.getUri(), claim);
        }
    }

    protected void populateClaimValues(String userIdentifier, SAMLAttributeCallback callback)
            throws IdentityProviderException {

        UserStoreManager connector = null;
        RahasData rahasData = null;

        if (log.isDebugEnabled()) {
            log.debug("Populating claim values");
        }

        if (requestedClaims.isEmpty()) {
            return;
        }

        // get the column names for the URIs
        Iterator<RequestedClaimData> ite = requestedClaims.values().iterator();
        List<String> claimList = new ArrayList<String>();
        rahasData = callback.getData();
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) rahasData.getInMessageContext()
                .getProperty(AUTHENTICATED_USER);

        while (ite.hasNext()) {
            RequestedClaimData claim = ite.next();
            if (claim != null && !claim.getUri().equals(IdentityConstants.CLAIM_PPID)) {
                claimList.add(claim.getUri());
            }
        }

        String[] claimArray = new String[claimList.size()];
        String userId = userIdentifier;
        Map<String, String> mapValues = null;

        try {
            if (MapUtils.isEmpty(requestedClaimValues)) {
                try {
                    // WS trust flow does not set the authenticated user property.
                    String tenantDomain;
                    if (authenticatedUser == null) {
                        // If authenticated user is not available, then the user is derived from the provided user
                        // identifier, and the tenant domain is derived from the current context.
                        tenantDomain = getTenantDomainFromThreadLocalContext();
                        UserRealm userRealm = tenantDomain != null ? IdentityTenantUtil.getRealm(tenantDomain,
                                null) : IdentityTenantUtil.getRealm(null, userId);
                        connector = userRealm.getUserStoreManager();
                        mapValues = connector.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(userId),
                                claimList.toArray(claimArray), null);
                    } else if (isHandlerCalledFromWSTrustSTSFlow(callback)) {
                        // WS trust flow does not set the authenticated user property.
                        connector = IdentityTenantUtil.getRealm(null, userId).
                                getUserStoreManager();
                        mapValues = connector.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(userId),
                                claimList.toArray(claimArray), null);
                    } else if (!authenticatedUser.isFederatedUser()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Loading claim values from local UserStore for user: "
                                    + authenticatedUser.toString());
                        }
                        tenantDomain = authenticatedUser.getTenantDomain();
                        connector = IdentityTenantUtil.getRealm(tenantDomain, null).
                                getUserStoreManager();
                        mapValues = connector.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(userId),
                                claimList.toArray(claimArray), null);
                    }
                } catch (UserStoreException e) {
                    throw new IdentityProviderException("Error while instantiating IdentityUserStore", e);
                }
            } else {
                mapValues = requestedClaimValues;
            }

            String claimSeparator = mapValues.get(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
            if (StringUtils.isNotBlank(claimSeparator)) {
                userAttributeSeparator = claimSeparator;
                mapValues.remove(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
            }

            ite = requestedClaims.values().iterator();
            while (ite.hasNext()) {
                SAMLAttribute attribute = null;
                Attribute saml2Attribute = null;
                RequestedClaimData claimData = ite.next();
                claimData.setValue(mapValues.get(claimData.getUri()));
                if (claimData.getValue() != null) {
                    if (RahasConstants.TOK_TYPE_SAML_20.equals(rahasData.getTokenType())) {
                        saml2Attribute = getSAML2Attribute(claimData.getUri(),
                                claimData.getValue(), claimData.getUri());
                        callback.addAttributes(saml2Attribute);
                    } else {
                        String name;
                        String nameSpace;
                        if (supportedClaims.get(claimData.getUri()) != null) {
                            name = supportedClaims.get(claimData.getUri()).getDisplayTag();
                            nameSpace = claimData.getUri();
                        } else {
                            nameSpace = claimData.getUri();
                            if (nameSpace.contains("/") && nameSpace.length() > (nameSpace.lastIndexOf("/") + 1)) {
                                // Custom claim uri should be in a format of http(s)://nameSpace/name.
                                name = nameSpace.substring(nameSpace.lastIndexOf("/") + 1);
                                nameSpace = nameSpace.substring(0, nameSpace.lastIndexOf("/"));
                            } else {
                                name = nameSpace;
                            }
                        }

                        List<String> values = new ArrayList<>();

                        if (claimData.getValue().contains(userAttributeSeparator)) {
                            StringTokenizer st = new StringTokenizer(claimData.getValue(), userAttributeSeparator);
                            while (st.hasMoreElements()) {
                                String attValue = st.nextElement().toString();
                                if (attValue != null && attValue.trim().length() > 0) {
                                    values.add(attValue);
                                }
                            }
                        } else {
                            values.add(claimData.getValue());
                        }

                        attribute = new SAMLAttribute(name, nameSpace, null, -1, values);
                        callback.addAttributes(attribute);
                    }
                }
            }
        } catch (Exception e) {
            throw new IdentityProviderException(e.getMessage(), e);
        }
    }

    protected RequestedClaimData getRequestedClaim() {

        return new RequestedClaimData();
    }

    private boolean isHandlerCalledFromWSTrustSTSFlow(SAMLAttributeCallback attributeCallback) {

        /*
        Authenticated user property is properly set during a passive STS flow. It is not done in the WS Trust based
        flow.
         */
        return !(attributeCallback.getData().getInMessageContext().getProperty(AUTHENTICATED_USER) instanceof
                AuthenticatedUser);
    }

    private String getTenantDomainFromThreadLocalContext() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }
}
