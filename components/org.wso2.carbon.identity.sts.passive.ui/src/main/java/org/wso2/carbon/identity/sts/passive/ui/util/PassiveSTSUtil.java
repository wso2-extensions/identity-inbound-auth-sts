/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sts.passive.ui.util;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sts.passive.ui.PassiveSTSException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;

public class PassiveSTSUtil {

    public static String getRetryUrl(){
        String retryUrl = IdentityUtil.getProperty(IdentityConstants.ServerConfig.PASSIVE_STS_RETRY);
        if (StringUtils.isBlank(retryUrl)){
            retryUrl = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
        }

        return retryUrl;
    }

    /**
     * Send user to the error page.
     *
     * @param request   Http servlet request.
     * @param response  Http servlet response.
     * @param status    Status to be displayed in the error page.
     * @param statusMsg Status message to be displayed in the error page.
     * @throws IOException          Error when sending the redirect.
     * @throws PassiveSTSException  Error building the redirect url of the error page.
     */
    public static void sendToErrorPage(HttpServletRequest request, HttpServletResponse response, String status,
                                       String statusMsg) throws IOException, PassiveSTSException {

        String errorURL = getErrorURL(status, statusMsg);
        String redirectURL = FrameworkUtils.getRedirectURL(errorURL, request);
        response.sendRedirect(redirectURL);
    }

    /**
     * Get the url of the error page.
     *
     * @param status        Status to be displayed in the error page.
     * @param statusMsg     Status message to be displayed in the error page.
     * @return              URL of the error page.
     * @throws PassiveSTSException  Error building the redirect url of the error page.
     */
    private static String getErrorURL(String status, String statusMsg) throws PassiveSTSException {

        try {
            URIBuilder uriBuilder = new URIBuilder(
                    ConfigurationFacade.getInstance().getAuthenticationEndpointErrorURL());
            uriBuilder.addParameter(FrameworkConstants.STATUS_PARAM, status);
            uriBuilder.addParameter(FrameworkConstants.STATUS_MSG_PARAM, statusMsg);
            return uriBuilder.build().toString();
        } catch (URISyntaxException e) {
            throw new PassiveSTSException("Error building the redirect url of the error page.", e);
        }
    }
}
