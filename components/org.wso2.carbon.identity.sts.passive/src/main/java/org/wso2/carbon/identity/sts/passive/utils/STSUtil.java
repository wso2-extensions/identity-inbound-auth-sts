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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.jaxws.context.WrappedMessageContext;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.security.SecurityContext;
import org.apache.cxf.sts.STSConstants;
import org.apache.cxf.sts.STSPropertiesMBean;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.claims.ClaimTypes;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.service.ServiceMBean;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.AuthenticationStatementProvider;
import org.apache.cxf.sts.token.provider.DefaultConditionsProvider;
import org.apache.cxf.sts.token.provider.DefaultSubjectProvider;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseCollectionType;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseType;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenType;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.sts.passive.custom.handler.PasswordCallbackHandler;
import org.wso2.carbon.identity.sts.passive.custom.provider.CustomAttributeProvider;
import org.wso2.carbon.identity.sts.passive.custom.provider.CustomAuthenticationProvider;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class STSUtil {

    private static final Log log = LogFactory.getLog(STSUtil.class);

//    public static String issueRSTR(String samlTokenType) throws Exception {
//
//        TokenIssueOperation issueOperation = new TokenIssueOperation();
//
//        addTokenProvider(issueOperation);
//
//        addService(issueOperation, "PassiveSTSSampleApp");
//
//        addSTSProperties(issueOperation, "localhost");
//
//        // Set the ClaimsManager to the issue operation.
//        ClaimsManager claimsManager = new ClaimsManager();
//        ClaimsHandler claimsHandler = new CustomClaimsHandler();
//        claimsManager.setClaimHandlers(Collections.singletonList(claimsHandler));
//        issueOperation.setClaimsManager(claimsManager);
//
//        // Mock up an issue request.
//        JAXBElement<String> tokenType;
//        RequestSecurityTokenType request = new RequestSecurityTokenType();
//        if (!samlTokenType.equals(WSS4JConstants.WSS_SAML2_TOKEN_TYPE)) {
//            tokenType = new JAXBElement<>(
//                    QNameConstants.TOKEN_TYPE, String.class, WSS4JConstants.WSS_SAML_TOKEN_TYPE
//            );
//        } else {
//            tokenType = new JAXBElement<>(
//                    QNameConstants.TOKEN_TYPE, String.class, WSS4JConstants.WSS_SAML2_TOKEN_TYPE
//            );
//        }
//        request.getAny().add(tokenType);
//        Element secondaryParameters = createSecondaryParameters();
//        request.getAny().add(secondaryParameters);
//        request.getAny().add(createAppliesToElement("PassiveSTSSampleApp"));
//
//        Map<String, Object> msgCtx = setupMessageContext("admin");
//
//        List<RequestSecurityTokenResponseType> securityTokenResponse = issueToken(issueOperation, request,
//                new CustomTokenPrincipal("admin"),
//                msgCtx);
//
//        JAXBElement<RequestSecurityTokenResponseType> jaxbResponse =
//                QNameConstants.WS_TRUST_FACTORY.createRequestSecurityTokenResponse(securityTokenResponse.get(0));
//
//        JAXBContext jaxbContext = JAXBContext.newInstance(RequestSecurityTokenResponseType.class);
//
//        // Create XML Formatted Response.
//        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
//        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
//        StringWriter sw = new StringWriter();
//        jaxbMarshaller.marshal(jaxbResponse, sw);
//
//        return changeNamespaces(sw.toString());
//    }

    /**
     * Issues a RSTR for the issue token RST.
     *
     * @param issueOperation The issue operation with the added properties.
     * @param request        The issue token request.
     * @param principal      The custom principal set.
     * @param msgCtx         The message context.
     * @return RSTR issued for the issue token RST.
     */
    public static RequestSecurityTokenResponseCollectionType issueToken(TokenIssueOperation issueOperation,
                                                                    RequestSecurityTokenType request, Principal principal, Map<String, Object> msgCtx) {

        return issueOperation.issue(request, principal, msgCtx);
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
     * Sets the required STS properties to the issue operation.
     *
     * @param issueOperation The issue operation which the STS properties should be set into.
     * @throws WSSecurityException If an error occurs while getting an instance from the CryptoFactory.
     */
    public static void addSTSProperties(TokenIssueOperation issueOperation, String issuer) throws WSSecurityException {

        STSPropertiesMBean stsProperties = new StaticSTSProperties();
        Crypto crypto = CryptoFactory.getInstance(getEncryptionProperties());
        stsProperties.setEncryptionCrypto(crypto);
        stsProperties.setSignatureCrypto(crypto);
        stsProperties.setEncryptionUsername("myservicekey");
        stsProperties.setSignatureUsername("mystskey");
        stsProperties.setCallbackHandler(new PasswordCallbackHandler());
        stsProperties.setIssuer(issuer);
        issueOperation.setStsProperties(stsProperties);
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
     * Sets the SAML token provider to the issue operation.
     *
     * @param issueOperation The issue operation which the token provider should be set into.
     */
    public static void addTokenProvider(TokenIssueOperation issueOperation) {

        List<TokenProvider> providerList = new ArrayList<>();

        List<AttributeStatementProvider> customProviderList =
                new ArrayList<>();
//        customProviderList.add(new CustomAttributeProvider());
        SAMLTokenProvider samlTokenProvider = new SAMLTokenProvider();

        DefaultConditionsProvider conditionsProvider = new DefaultConditionsProvider();
        conditionsProvider.setAcceptClientLifetime(true);
        String lifeTime = ServerConfiguration.getInstance().getFirstProperty("STSTimeToLive");
        if (lifeTime != null && lifeTime.length() > 0) {
            try {
                conditionsProvider.setLifetime(Long.parseLong(lifeTime));
                if (log.isDebugEnabled()) {
                    log.debug("STSTimeToLive read from carbon.xml in passive STS " + lifeTime);
                }
            } catch (NumberFormatException e) {
                log.error("Error while reading STSTimeToLive from carbon.xml", e);
            }
        }
        samlTokenProvider.setConditionsProvider(conditionsProvider);

        DefaultSubjectProvider subjectProvider = new DefaultSubjectProvider();
        // The constant is same for SAML1.1 and SAML2.
        subjectProvider.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
        samlTokenProvider.setSubjectProvider(subjectProvider);

        List<AuthenticationStatementProvider> customAuthenticationProviderList =
                new ArrayList<>();
        customAuthenticationProviderList.add(new CustomAuthenticationProvider());
        samlTokenProvider.setAuthenticationStatementProviders(customAuthenticationProviderList);

//        samlTokenProvider.setAttributeStatementProviders(customProviderList);
        providerList.add(samlTokenProvider);
        issueOperation.setTokenProviders(providerList);
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
     * Mock up an AppliesTo element using the supplied address.
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
     * Mock up a SecondaryParameters DOM Element containing some claims.
     *
     * @return Element containing the created secondary parameters.
     */
    public static Element createSecondaryParameters() {

        Document doc = DOMUtils.getEmptyDocument();
        Element secondary = doc.createElementNS(STSConstants.WST_NS_05_12, "SecondaryParameters");
        secondary.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns", STSConstants.WST_NS_05_12);

        Element claims = doc.createElementNS(STSConstants.WST_NS_05_12, "Claims");
        claims.setAttributeNS(null, "Dialect", STSConstants.IDT_NS_05_05);

        Element claimType = createClaimsType(doc);
        claims.appendChild(claimType);
        secondary.appendChild(claims);

        return secondary;
    }

    /**
     * Creates a claim type element inside the document.
     *
     * @param document The document which the claim type element is created.
     * @return The created claim type element.
     */
    private static Element createClaimsType(Document document) {

        Element claimType = document.createElementNS(STSConstants.IDT_NS_05_05, "ClaimType");
        claimType.setAttributeNS(
                null, "Uri", ClaimTypes.LASTNAME.toString()
        );
        claimType.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns", STSConstants.IDT_NS_05_05);

        return claimType;
    }

    /**
     * Set the encryption properties to a properties object and return it.
     *
     * @return Properties object containing the encryption properties.
     */
    private static Properties getEncryptionProperties() {

        Properties properties = new Properties();
        properties.put(
                "org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin"
        );
        properties.put("org.apache.wss4j.crypto.merlin.keystore.password", "stsspass");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.file", "keys/stsstore.jks");

        return properties;
    }

    /**
     * Change the namespaces of the default generated RSTR.
     *
     * @param response Default generated Request Security Token Response in the form of a string.
     * @return RSTR with the changed namespaces.
     */
    public static String changeNamespaces(String response) {

        return response.
                replaceAll("ns2", "wst").
                replaceAll("ns3", "wsu").
                replaceAll("ns4", "wsse");
    }
}
