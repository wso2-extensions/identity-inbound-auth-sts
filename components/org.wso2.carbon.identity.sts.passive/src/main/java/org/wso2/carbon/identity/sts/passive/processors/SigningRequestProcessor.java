/*
 *  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sts.passive.processors;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.sts.QNameConstants;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsManager;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseCollectionType;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenType;;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.w3c.dom.Element;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.sts.passive.RequestToken;
import org.wso2.carbon.identity.sts.passive.ResponseToken;
import org.wso2.carbon.identity.sts.passive.custom.handler.CustomClaimsHandler;
import org.wso2.carbon.identity.sts.passive.internal.IdentityPassiveSTSServiceComponent;
import org.wso2.carbon.identity.sts.passive.utils.PassiveSTSUtil;
import org.wso2.carbon.user.api.UserStoreException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.StringWriter;
import java.util.Collections;
import java.util.Map;

import static org.wso2.carbon.identity.sts.passive.utils.STSUtil.addSTSProperties;
import static org.wso2.carbon.identity.sts.passive.utils.STSUtil.addService;
import static org.wso2.carbon.identity.sts.passive.utils.STSUtil.addTokenProvider;
import static org.wso2.carbon.identity.sts.passive.utils.STSUtil.changeNamespaces;
import static org.wso2.carbon.identity.sts.passive.utils.STSUtil.createAppliesToElement;
import static org.wso2.carbon.identity.sts.passive.utils.STSUtil.createSecondaryParameters;
import static org.wso2.carbon.identity.sts.passive.utils.STSUtil.issueToken;
import static org.wso2.carbon.identity.sts.passive.utils.STSUtil.setupMessageContext;

public class SigningRequestProcessor extends RequestProcessor {

    private static final Log log = LogFactory.getLog(SigningRequestProcessor.class);

    public static final String STS_SIGNATURE_ALGORITHM = "Security.STSSignatureAlgorithm";
    public static final String STS_DIGEST_ALGORITHM = "Security.STSDigestAlgorithm";

    public ResponseToken process(RequestToken request) throws STSException {

        ResponseToken responseToken;
        String tenantDomain = null;
        try {
            tenantDomain = request.getTenantDomain();
            int tenantId = IdentityPassiveSTSServiceComponent.getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            if (StringUtils.isNotEmpty(tenantDomain)) {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
            }

            TokenIssueOperation issueOperation = new TokenIssueOperation();

            addTokenProvider(issueOperation);

            addService(issueOperation, request.getRealm());

            addSTSProperties(issueOperation, "localhost");

            // Set the ClaimsManager to the issue operation.
            ClaimsManager claimsManager = new ClaimsManager();
            ClaimsHandler claimsHandler = new CustomClaimsHandler();
            claimsManager.setClaimHandlers(Collections.singletonList(claimsHandler));
            issueOperation.setClaimsManager(claimsManager);

            String requestedTokenType = PassiveSTSUtil.extractTokenType(request);

            // Mock up an issue request.
            JAXBElement<String> tokenType;
            RequestSecurityTokenType issueTokenRequest = new RequestSecurityTokenType();
            if (!WSS4JConstants.WSS_SAML2_TOKEN_TYPE.equals(requestedTokenType)) {
                tokenType = new JAXBElement<>(
                        QNameConstants.TOKEN_TYPE, String.class, WSS4JConstants.WSS_SAML_TOKEN_TYPE
                );
            } else {
                tokenType = new JAXBElement<>(
                        QNameConstants.TOKEN_TYPE, String.class, WSS4JConstants.WSS_SAML2_TOKEN_TYPE
                );
            }
            issueTokenRequest.getAny().add(tokenType);
            Element secondaryParameters = createSecondaryParameters();
            issueTokenRequest.getAny().add(secondaryParameters);
            issueTokenRequest.getAny().add(createAppliesToElement(request.getRealm()));

            Map<String, Object> msgCtx = setupMessageContext(request.getUserName());

            RequestSecurityTokenResponseCollectionType securityTokenResponse = issueToken(issueOperation, issueTokenRequest,
                    new CustomTokenPrincipal(request.getUserName()),
                    msgCtx);

            JAXBElement<RequestSecurityTokenResponseCollectionType> jaxbResponse =
                    QNameConstants.WS_TRUST_FACTORY.createRequestSecurityTokenResponseCollection(securityTokenResponse);

            StringWriter sw = new StringWriter();
            try {
                // Create XML Formatted Response.
                JAXBContext jaxbContext = JAXBContext.newInstance(RequestSecurityTokenResponseCollectionType.class);
                Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
                jaxbMarshaller.marshal(jaxbResponse, sw);
            } catch (JAXBException exception) {
                log.error(exception.getMessage(), exception);
                throw new STSException("Error while processing the sign-in request.", exception);
            }

            responseToken = new ResponseToken();
            responseToken.setResults(changeNamespaces(sw.toString()));

        } catch (UserStoreException e) {
            log.error("Error while getting tenant Id from realm service.", e);
            throw new STSException("Error while processing the sign-in request.", e);
        } catch (Exception e) {
            log.error("Failed to add the STS configurations.", e);
            throw new STSException("Error while processing the sign-in request.", e);
        } finally {
            if (StringUtils.isNotEmpty(tenantDomain)) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }

        return responseToken;
    }
}
