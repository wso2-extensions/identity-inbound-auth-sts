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
import org.wso2.carbon.identity.sts.passive.stub.IdentityPassiveSTSServiceStub;
import org.wso2.carbon.identity.sts.passive.stub.types.ClaimDTO;
import org.wso2.carbon.identity.sts.passive.stub.types.RequestToken;
import org.wso2.carbon.identity.sts.passive.stub.types.ResponseToken;
import org.wso2.carbon.identity.sts.passive.ui.factories.PassiveSTSServiceFactory;

/**
 * Client facade for Passive STS operations.
 * This no longer uses SOAP stubs. It delegates to PassiveSTSService instead.
 */
public class IdentityPassiveSTSClient {

    private static final Log log = LogFactory.getLog(IdentityPassiveSTSClient.class);

    private final boolean soapEnabled;
    private IdentityPassiveSTSServiceStub soapStub;
    private final PassiveSTSService passiveSTSService;

    public IdentityPassiveSTSClient(String backendServerURL, ConfigurationContext configCtx) throws AxisFault {

        // Read toggle from config; default to PassiveSTSService to avoid SOAP dependency at runtime.
        String prop = IdentityUtil.getProperty("PassiveSTS.SOAPEnabled");
        this.soapEnabled = Boolean.parseBoolean(prop);

        if (this.soapEnabled) {
            String serviceURL = backendServerURL + "IdentityPassiveSTSService";
            soapStub = new IdentityPassiveSTSServiceStub(configCtx, serviceURL);
            ServiceClient client = soapStub._getServiceClient();
            Options option = client.getOptions();
            option.setManageSession(true);

            if (log.isDebugEnabled()) {
                log.debug("SOAP stub initialized for service URL: " + serviceURL);
            }
        }

        this.passiveSTSService = PassiveSTSServiceFactory.getPassiveSTSService();
    }

    public ResponseToken getResponse(RequestToken request) throws AxisFault {

        if (soapEnabled) {
            try {
                return soapStub.getResponse(request);
            } catch (Exception e) {
                handleException("Error occurred getting the response from the SOAP passive STS service", e);
            }
        } else {
            try {
                // Map stub RequestToken to in-process RequestToken.
                org.wso2.carbon.identity.sts.passive.RequestToken inReq = getRequestToken(request);

                org.wso2.carbon.identity.sts.passive.ResponseToken inResp = passiveSTSService.getResponse(inReq);

                // Map in-process ResponseToken back to stub ResponseToken.
                org.wso2.carbon.identity.sts.passive.stub.types.ResponseToken out =
                        new org.wso2.carbon.identity.sts.passive.stub.types.ResponseToken();
                out.setResults(inResp.getResults());
                out.setContext(inResp.getContext());
                out.setResponsePointer(inResp.getResponsePointer());
                out.setReplyTo(inResp.getReplyTo());
                out.setAuthenticated(inResp.isAuthenticated());
                return out;
            } catch (Exception e) {
                handleException("Error occurred getting the response from the PassiveSTSService", e);
            }
        }
        return null;
    }

    private static org.wso2.carbon.identity.sts.passive.RequestToken
        getRequestToken(org.wso2.carbon.identity.sts.passive.stub.types.RequestToken request) {

        org.wso2.carbon.identity.sts.passive.RequestToken inReq =
                new org.wso2.carbon.identity.sts.passive.RequestToken();
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

        if (soapEnabled) {
            try {
                soapStub.addTrustedService(realmName, claimDialect, claims);
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

        if (soapEnabled) {
            try {
                soapStub.removeTrustedService(realmName);
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

    public ClaimDTO[] getAllTrustedServices() throws AxisFault {

        if (soapEnabled) {
            try {
                return soapStub.getAllTrustedServices();
            } catch (Exception e) {
                handleException("Error occurred while getting all trusted services (SOAP).", e);
            }
        } else {
            try {
                org.wso2.carbon.identity.sts.passive.ClaimDTO[] in = passiveSTSService.getAllTrustedServices();
                if (in == null) {
                    return new ClaimDTO[0];
                }
                ClaimDTO[] out = new ClaimDTO[in.length];
                for (int i = 0; i < in.length; i++) {
                    ClaimDTO dto = new ClaimDTO();
                    dto.setRealm(in[i].getRealm());
                    dto.setDefaultClaims(in[i].getDefaultClaims());
                    dto.setClaimDialect(in[i].getClaimDialect());
                    out[i] = dto;
                }
                return out;
            } catch (Exception e) {
                handleException("Error occurred while getting all trusted services.", e);
            }
        }
        return new ClaimDTO[0];
    }

    /**
     * Logs and wraps the given exception.
     *
     * @param msg Error message
     * @param e   Exception
     * @throws org.apache.axis2.AxisFault
     */
    private void handleException(String msg, Exception e) throws AxisFault {

        throw new AxisFault(msg, e);
    }
}
