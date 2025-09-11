/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.sts.passive.ui.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sts.passive.PassiveSTSService;
import org.wso2.carbon.identity.sts.passive.ClaimDTO;
import org.wso2.carbon.identity.sts.passive.RequestToken;
import org.wso2.carbon.identity.sts.passive.ResponseToken;
import org.wso2.carbon.identity.sts.passive.stub.IdentityPassiveSTSServiceStub;
import org.wso2.carbon.identity.sts.passive.ui.factories.PassiveSTSServiceFactory;

/**
 * Backward-compatible client facade for Passive STS operations.
 *
 * This no longer uses SOAP stubs. It delegates to in-process services instead.
 */
public class IdentityPassiveSTSClient {

    private static final Log log = LogFactory.getLog(IdentityPassiveSTSClient.class);

    private final boolean useSoapService;
    private IdentityPassiveSTSServiceStub soapStub;
    private final PassiveSTSService passiveSTSService;

    public IdentityPassiveSTSClient(String backendServerURL, ConfigurationContext configCtx) throws AxisFault {

        // Read toggle from config; default to in-process to avoid SOAP dependency at runtime.
        String prop = IdentityUtil.getProperty("passive.sts.useSoapService");
        boolean useSoapService = false;
        this.useSoapService = (prop == null) ? useSoapService : !"false".equalsIgnoreCase(prop);

        String serviceURL = backendServerURL + "IdentityPassiveSTSService";
        soapStub = new IdentityPassiveSTSServiceStub(configCtx, serviceURL);
        ServiceClient client = soapStub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);

        this.passiveSTSService = PassiveSTSServiceFactory.getPassiveSTSService();
    }

    public org.wso2.carbon.identity.sts.passive.stub.types.ResponseToken getResponse(
            org.wso2.carbon.identity.sts.passive.stub.types.RequestToken request) throws AxisFault {

        if (useSoapService) {
            try {
                return soapStub.getResponse(request);
            } catch (Exception e) {
                handleException("Error occurred getting the response from the SOAP passive STS service", e);
            }
            return null;
        } else {

            try {
                // Map stub RequestToken to in-process RequestToken
                RequestToken inReq = getRequestToken(request);

                ResponseToken inResp = passiveSTSService.getResponse(inReq);

                // Map in-process ResponseToken back to stub ResponseToken
                org.wso2.carbon.identity.sts.passive.stub.types.ResponseToken out =
                        new org.wso2.carbon.identity.sts.passive.stub.types.ResponseToken();
                out.setResults(inResp.getResults());
                out.setContext(inResp.getContext());
                out.setResponsePointer(inResp.getResponsePointer());
                out.setReplyTo(inResp.getReplyTo());
                out.setAuthenticated(inResp.isAuthenticated());
                return out;
            } catch (Exception e) {
                handleException("Error occurred getting the response from the in-process passive STS service", e);
            }
            return null;
        }
    }

    private static RequestToken getRequestToken(org.wso2.carbon.identity.sts.passive.stub.types.RequestToken request) {
        RequestToken inReq = new RequestToken();
        inReq.setAction(request.getAction());
        inReq.setReplyTo(request.getReplyTo());
        inReq.setResponseTo(request.getResponseTo());
        inReq.setContext(request.getContext());
        inReq.setPolicy(request.getPolicy());
        inReq.setCurrentTimeAtRecepient(request.getCurrentTimeAtRecepient());
        inReq.setRealm(request.getRealm());
        inReq.setRequest(request.getRequest());
        inReq.setRequestPointer(request.getRequestPointer());
        inReq.setAttributes(request.getAttributes());
        inReq.setPseudo(request.getPseudo());
        inReq.setUserName(request.getUserName());
        inReq.setPassword(request.getPassword());
        inReq.setDialect(request.getDialect());
        inReq.setTenantDomain(request.getTenantDomain());
        return inReq;
    }

    public void addTrustedService(String realmName, String claimDialect, String claims) throws AxisFault {
        if (useSoapService) {
            try {
                soapStub.addTrustedService(realmName, claimDialect, claims);
                return;
            } catch (Exception e) {
                handleException("Error occurred while adding the trusted service: " + realmName, e);
            }
        } else {
            try {
                passiveSTSService.addTrustedService(realmName, claimDialect, claims);
            } catch (Exception e) {
                handleException("Error occurred while adding the trusted service: " + realmName, e);
            }
        }
    }

    public void removeTrustedService(String realmName) throws AxisFault {
        if (useSoapService) {
            try {
                soapStub.removeTrustedService(realmName);
                return;
            } catch (Exception e) {
                handleException("Error occurred while removing the trusted service: " + realmName, e);
            }
        } else {
            try {
                passiveSTSService.removeTrustedService(realmName);
            } catch (Exception e) {
                handleException("Error occurred while removing the trusted service: " + realmName, e);
            }
        }
    }

    public org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO[] getAllTrustedServices() throws AxisFault {
        if (useSoapService) {
            try {
                return soapStub.getAllTrustedServices();
            } catch (Exception e) {
                handleException("Error occurred while getting all trusted services (SOAP).", e);
            }
            return new org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO[0];
        } else {
            try {
                ClaimDTO[] in = passiveSTSService.getAllTrustedServices();
                if (in == null) {
                    return new org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO[0];
                }
                org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO[] out =
                        new org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO[in.length];
                for (int i = 0; i < in.length; i++) {
                    org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO dto =
                            new org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO();
                    dto.setRealm(in[i].getRealm());
                    dto.setDefaultClaims(in[i].getDefaultClaims());
                    dto.setClaimDialect(in[i].getClaimDialect());
                    out[i] = dto;
                }
                return out;
            } catch (Exception e) {
                handleException("Error occurred while getting all trusted services.", e);
            }
            return new org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO[0];
        }
    }

    /**
     * Logs and wraps the given exception.
     *
     * @param msg Error message
     * @param e   Exception
     * @throws org.apache.axis2.AxisFault
     */
    private void handleException(String msg, Exception e) throws AxisFault {
        log.error(msg, e);
        throw new AxisFault(msg, e);
    }
}
