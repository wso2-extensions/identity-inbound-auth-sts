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
package org.wso2.carbon.identity.sts.passive.utils;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.jaxws.context.WrappedMessageContext;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.security.SecurityContext;
import org.apache.cxf.sts.STSConstants;
import org.apache.cxf.sts.STSPropertiesMBean;
import org.apache.cxf.sts.SignatureProperties;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.claims.ClaimsManager;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.service.ServiceMBean;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.AuthenticationStatementProvider;
import org.apache.cxf.sts.token.provider.DefaultConditionsProvider;
import org.apache.cxf.sts.token.provider.DefaultSubjectProvider;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseCollectionType;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenType;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sts.passive.RequestToken;
import org.wso2.carbon.identity.sts.passive.custom.handler.CustomClaimsHandler;
import org.wso2.carbon.identity.sts.passive.custom.handler.PasswordCallbackHandler;
import org.wso2.carbon.identity.sts.passive.custom.provider.CustomAttributeProvider;
import org.wso2.carbon.identity.sts.passive.custom.provider.CustomAuthenticationProvider;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.sts.passive.PassiveRequestorConstants.STS_DIGEST_ALGORITHM_KEY;
import static org.wso2.carbon.identity.sts.passive.PassiveRequestorConstants.STS_SIGNATURE_ALGORITHM_KEY;
import static org.wso2.carbon.identity.sts.passive.PassiveRequestorConstants.STS_TIME_TO_LIVE_KEY;

public class RequestProcessorUtil {

    private static final Log log = LogFactory.getLog(RequestProcessorUtil.class);

    /**
     * Sets the SAML token provider to the issue operation.
     *
     * @param issueOperation The issue operation which the token provider should be set into.
     * @param requestToken   Request sent by the client to obtain the security token.
     */
    public static void addTokenProvider(TokenIssueOperation issueOperation, RequestToken requestToken) {

        List<TokenProvider> providerList = new ArrayList<>();
        SAMLTokenProvider samlTokenProvider = new SAMLTokenProvider();

        if (getFormattedClaims(requestToken.getAttributes()).size() > 0) {
            List<AttributeStatementProvider> customProviderList =
                    new ArrayList<>();
            customProviderList.add(new CustomAttributeProvider());
            samlTokenProvider.setAttributeStatementProviders(customProviderList);
        }

        DefaultConditionsProvider conditionsProvider = new DefaultConditionsProvider();
        conditionsProvider.setAcceptClientLifetime(true);
        String lifeTime = ServerConfiguration.getInstance().getFirstProperty(STS_TIME_TO_LIVE_KEY);
        if (lifeTime != null && lifeTime.length() > 0) {
            try {
                conditionsProvider.setLifetime(Long.parseLong(lifeTime));
                if (log.isDebugEnabled()) {
                    log.debug("STSTimeToLive read from carbon.xml in passive STS " + lifeTime);
                }
            } catch (NumberFormatException e) {
                log.error("Error while reading STSTimeToLive from carbon.xml", e);
            }
        } else {
            // Set lifetime to 5 minutes by default.
            conditionsProvider.setLifetime(300);
        }
        samlTokenProvider.setConditionsProvider(conditionsProvider);

        DefaultSubjectProvider subjectProvider = new DefaultSubjectProvider();
        // The constant is same for SAML1.1 and SAML2.0.
        subjectProvider.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
        samlTokenProvider.setSubjectProvider(subjectProvider);

        List<AuthenticationStatementProvider> customAuthenticationProviderList =
                new ArrayList<>();
        customAuthenticationProviderList.add(new CustomAuthenticationProvider());
        samlTokenProvider.setAuthenticationStatementProviders(customAuthenticationProviderList);

        providerList.add(samlTokenProvider);
        issueOperation.setTokenProviders(providerList);
    }

    /**
     * Get a formatted HashMap of claims containing the URI as the key and attribute value as the value.
     *
     * @param attributes Attributes sent by the client in the request..
     * @return Formatted HashMap containing the claims.
     */
    private static HashMap<String, String> getFormattedClaims(String attributes) {

        HashMap<String, String> formattedClaims = new HashMap<>();
        String[] formattedAttributes;

        if (attributes != null) {
            if (attributes.contains("#CODE#")) {
                formattedAttributes = attributes.split("#CODE#");
            } else {
                formattedAttributes = attributes.split(",");
            }
            for (String attribute : formattedAttributes) {
                if (!attribute.contains("Multi")) {
                    attribute = attribute.replaceAll("[{}]", "");
                    String[] separatedAttribute = attribute.split("\\|");
                    if (FrameworkConstants.IDP_MAPPED_USER_ROLES.equals(separatedAttribute[0])) {
                        continue;
                    }
                    if (separatedAttribute.length > 1) {
                        formattedClaims.put(separatedAttribute[0], separatedAttribute[1]);
                    } else {
                        formattedClaims.put(separatedAttribute[0], StringUtils.EMPTY);
                    }
                }
            }
        }

        return formattedClaims;
    }

    /**
     * Sets the service to the issue operation. In our case it is the realm.
     *
     * @param issueOperation The issue operation which the service should be set into.
     */
    public static void addService(TokenIssueOperation issueOperation, String appliesTo) {

        ServiceMBean service = new StaticService();
        service.setEndpoints(Collections.singletonList(appliesTo));

        issueOperation.setServices(Collections.singletonList(service));
    }

    /**
     * Sets the required STS properties to the issue operation.
     *
     * @param issueOperation The issue operation which the STS properties should be set into.
     * @throws Exception If an error occurs while getting an instance from the CryptoFactory,
     *                   while obtaining the keystore password, if the key alias is null or
     *                   while obtaining the issuer name.
     */
    public static void addSTSProperties(TokenIssueOperation issueOperation) throws Exception {

        Crypto crypto = CryptoFactory.getInstance(getEncryptionProperties());

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String keyAlias = IdentityKeyStoreResolver.getInstance().getKeyStoreConfig(
                tenantDomain,
                IdentityKeyStoreResolverConstants.InboundProtocol.WS_FEDERATION,
                RegistryResources.SecurityManagement.CustomKeyStore.PROP_KEY_ALIAS);

        if (keyAlias == null) {
            throw new STSException("Private key alias cannot be null.");
        }

        ServerConfiguration serverConfig = ServerConfiguration.getInstance();
        String signatureAlgorithm = serverConfig.getFirstProperty(STS_SIGNATURE_ALGORITHM_KEY);
        String digestAlgorithm = serverConfig.getFirstProperty(STS_DIGEST_ALGORITHM_KEY);

        STSPropertiesMBean stsProperties = new StaticSTSProperties();
        stsProperties.setEncryptionCrypto(crypto);
        stsProperties.setSignatureCrypto(crypto);
        stsProperties.setEncryptionUsername(keyAlias);
        stsProperties.setSignatureUsername(keyAlias);
        stsProperties.setCallbackHandler(new PasswordCallbackHandler());
        stsProperties.setIssuer(getIssuerName());

        SignatureProperties signatureProperties = new SignatureProperties();
        if (!signatureProperties.getAcceptedSignatureAlgorithms().contains(signatureAlgorithm)) {
            signatureProperties.setAcceptedSignatureAlgorithms(
                    Collections.singletonList(signatureAlgorithm));
        }
        signatureProperties.setSignatureAlgorithm(signatureAlgorithm);
        signatureProperties.setDigestAlgorithm(digestAlgorithm);

        stsProperties.setSignatureProperties(signatureProperties);

        issueOperation.setStsProperties(stsProperties);
    }

    /**
     * Get the keystore alias and the key store password.
     *
     * @param tenantId     The tenant Id.
     * @param tenantDomain The tenant domain.
     * @return aliasAndPassword A string array which contains the keystore
     * alias and password.
     * @throws Exception If there is an error while obtaining the keystore password.
     */
    public static String[] getKeyStoreAliasAndKeyStorePassword(
            ServerConfiguration serverConfig, int tenantId, String tenantDomain) throws Exception {

        String[] aliasAndPassword = new String[2];

        aliasAndPassword[0] = IdentityKeyStoreResolver.getInstance().getKeyStoreConfig(
                tenantDomain,
                IdentityKeyStoreResolverConstants.InboundProtocol.WS_FEDERATION,
                RegistryResources.SecurityManagement.CustomKeyStore.PROP_KEY_ALIAS);
        aliasAndPassword[1] = IdentityKeyStoreResolver.getInstance().getKeyStoreConfig(
                tenantDomain,
                IdentityKeyStoreResolverConstants.InboundProtocol.WS_FEDERATION,
                RegistryResources.SecurityManagement.CustomKeyStore.PROP_PASSWORD);

        return aliasAndPassword;
    }

    /**
     * Set the encryption properties to a properties object and return it.
     *
     * @return Properties object containing the encryption properties.
     */
    private static Properties getEncryptionProperties() throws IdentityKeyStoreResolverException {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();

        String keyStoreFileLocation = IdentityKeyStoreResolver.getInstance().getKeyStoreConfig(
                tenantDomain,
                IdentityKeyStoreResolverConstants.InboundProtocol.WS_FEDERATION,
                RegistryResources.SecurityManagement.CustomKeyStore.PROP_LOCATION);
        String keyStorePassword = IdentityKeyStoreResolver.getInstance().getKeyStoreConfig(
                tenantDomain,
                IdentityKeyStoreResolverConstants.InboundProtocol.WS_FEDERATION,
                RegistryResources.SecurityManagement.CustomKeyStore.PROP_PASSWORD);

        String tenantKeyStoreName = IdentityKeyStoreResolverUtil.buildTenantKeyStoreName(tenantDomain);

        if (StringUtils.isEmpty(keyStoreFileLocation) || StringUtils.isEmpty(keyStorePassword)) {
            throw new STSException("Error occoured when building encryption properties." +
                    " One or more keystore properties are null or empty.");
        }

        Properties properties = new Properties();

        properties.put("org.apache.wss4j.crypto.provider",
                "org.wso2.carbon.identity.sts.passive.custom.provider.CustomCryptoProvider");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.file", keyStoreFileLocation);
        properties.put("org.apache.wss4j.crypto.merlin.keystore.password", keyStorePassword);

        // If the keystore is a tenant keystore, it cannot be loaded from the file location.
        // Passing tenant id and keystore name for the keystore to be loaded using the CustomCryptoProvider class.
        if (MultitenantConstants.SUPER_TENANT_ID != tenantId && keyStoreFileLocation.equals(tenantKeyStoreName)) {
            properties.put("org.apache.wss4j.crypto.merlin.keystore.tenant.id", String.valueOf(tenantId));
            properties.put("org.apache.wss4j.crypto.merlin.keystore.name", tenantKeyStoreName);
            properties.put("org.apache.wss4j.crypto.merlin.keystore.file", "");
        }

        return properties;
    }

    /**
     * Get the name of the issuer of the request.
     *
     * @return Name of the issuer.
     * @throws Exception If there is an error in retrieving the resident identity provider.
     */
    private static String getIssuerName() throws Exception {

        IdentityProvider identityProvider;
        String issuerName;
        String idPEntityId = null;
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        try {
            identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (Exception exception) {
            throw new Exception(
                    "Error occurred while retrieving Resident Identity Provider information for tenant "
                            + tenantDomain, exception);
        }

        FederatedAuthenticatorConfig config = IdentityApplicationManagementUtil
                .getFederatedAuthenticator(identityProvider.getFederatedAuthenticatorConfigs(),
                        IdentityApplicationConstants.Authenticator.PassiveSTS.NAME);
        Property property = IdentityApplicationManagementUtil.getProperty(config.getProperties(),
                IdentityApplicationConstants.Authenticator.PassiveSTS.IDENTITY_PROVIDER_ENTITY_ID);

        if (property != null) {
            idPEntityId = property.getValue();
        }

        if (idPEntityId == null) {
            idPEntityId = IdentityUtil.getProperty(IdentityConstants.ServerConfig.ENTITY_ID);
        }

        issuerName = idPEntityId;

        if (issuerName == null) {
            // If the host name is not set.
            issuerName = "Identity-passive-sts";
        }

        return issuerName;
    }

    /**
     * Handles the claim related logic. For example setting the known URIs.
     *
     * @param requestToken   Request sent by the client to obtain the security token.
     * @param issueOperation The issue operation which the claim manager should be set into.
     */
    public static void handleClaims(RequestToken requestToken, TokenIssueOperation issueOperation) {

        CustomClaimsHandler customClaimsHandler = new CustomClaimsHandler();
        CustomClaimsHandler.setKnownURIs(getClaimURIs(requestToken.getAttributes()));
        customClaimsHandler.setRequestedClaims(getFormattedClaims(requestToken.getAttributes()));

        ClaimsManager claimsManager = new ClaimsManager();
        claimsManager.setClaimHandlers(Collections.singletonList(customClaimsHandler));

        issueOperation.setClaimsManager(claimsManager);
    }

    /**
     * Create a SecondaryParameters DOM Element containing the required claims.
     *
     * @param requestToken Request sent by the client to obtain the security token.
     * @return Element containing the created secondary parameters.
     */
    public static Element createSecondaryParameters(RequestToken requestToken) {

        Document doc = DOMUtils.getEmptyDocument();
        Element secondary = doc.createElementNS(STSConstants.WST_NS_05_12, "SecondaryParameters");
        secondary.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns", STSConstants.WST_NS_05_12);

        Element claims = doc.createElementNS(STSConstants.WST_NS_05_12, "Claims");
        claims.setAttributeNS(null, "Dialect", STSConstants.IDT_NS_05_05);

        List<String> requestedClaimURIs = getClaimURIs(requestToken.getAttributes());

        // Iterates through the claims and inserts them.
        for (String claimURI : requestedClaimURIs) {
            Element claimType = createClaimsType(doc, claimURI);
            claims.appendChild(claimType);
            secondary.appendChild(claims);
        }

        return secondary;
    }

    /**
     * Obtain the claim URIs with the help of method getFormattedClaims(String attributes).
     *
     * @param attributes Attributes sent by the client in the request.
     * @return List of claim URIs.
     */
    private static List<String> getClaimURIs(String attributes) {

        List<String> claimURIs = new ArrayList<>();
        HashMap<String, String> formattedClaims = getFormattedClaims(attributes);

        for (Map.Entry claim : formattedClaims.entrySet()) {
            claimURIs.add(claim.getKey().toString());
        }

        return claimURIs;
    }

    /**
     * Creates a claim type element inside the document.
     *
     * @param document The document which the claim type element is created.
     * @param claimURI The claim URI.
     * @return The created claim type element.
     */
    private static Element createClaimsType(Document document, String claimURI) {

        Element claimType = document.createElementNS(STSConstants.IDT_NS_05_05, "ClaimType");
        claimType.setAttributeNS(
                null, "Uri", URI.create(claimURI).toString()
        );
        claimType.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns", STSConstants.IDT_NS_05_05);

        return claimType;
    }

    /**
     * Create an AppliesTo element using the supplied address.
     *
     * @param addressUrl The address url or the realm in our case.
     * @return AppliesTo element which is created.
     */
    public static Element createAppliesToElement(String addressUrl) {

        Document doc = DOMUtils.getEmptyDocument();
        Element appliesTo = doc.createElementNS(STSConstants.WSP_NS, "wsp:AppliesTo");
        appliesTo.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:wsp", STSConstants.WSP_NS);
        Element endpointRef = doc.createElementNS(STSConstants.WSA_NS_05, "wsa:EndpointReference");
        endpointRef.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:wsa", STSConstants.WSA_NS_05);
        Element address = doc.createElementNS(STSConstants.WSA_NS_05, "wsa:Address");
        address.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:wsa", STSConstants.WSA_NS_05);
        address.setTextContent(addressUrl);
        endpointRef.appendChild(address);
        appliesTo.appendChild(endpointRef);
        return appliesTo;
    }

    /**
     * Set up a message context with the custom token principal.
     *
     * @return The created message context.
     */
    public static Map<String, Object> setupMessageContext(String userName) {

        MessageImpl msg = new MessageImpl();
        WrappedMessageContext msgCtx = new WrappedMessageContext(msg);
        msgCtx.put(
                SecurityContext.class.getName(),
                createSecurityContext(new CustomTokenPrincipal(userName))
        );
        return msgCtx;
    }

    /**
     * Create a security context object.
     *
     * @param principal The custom principal to be set into the context object.
     * @return Created security context object.
     */
    private static SecurityContext createSecurityContext(final Principal principal) {

        return new SecurityContext() {

            public Principal getUserPrincipal() {

                return principal;
            }

            public boolean isUserInRole(String role) {

                return false;
            }
        };
    }

    /**
     * Issues a RSTR for the issue token RST.
     *
     * @param issueOperation The issue operation with the added properties.
     * @param request        The issue token request.
     * @param principal      The custom principal set.
     * @param msgCtx         The message context.
     * @return RSTR issued for the issue token RST.
     */
    public static RequestSecurityTokenResponseCollectionType issueToken(
            TokenIssueOperation issueOperation, RequestSecurityTokenType request,
            Principal principal, Map<String, Object> msgCtx) {

        return issueOperation.issue(request, principal, msgCtx);
    }

    /**
     * Change the namespaces of the default generated RSTR.
     *
     * @param response Default generated Request Security Token Response in the form of a string.
     * @return RSTR with the changed namespaces.
     */
    public static String changeNamespaces(String response) {

        // TODO - Improve this logic since the namespaces get scrambled time to time.
        return response.
                replaceAll("ns2", "wst").
                replaceAll("ns3", "wsu").
                replaceAll("ns4", "wsse");
    }
}
