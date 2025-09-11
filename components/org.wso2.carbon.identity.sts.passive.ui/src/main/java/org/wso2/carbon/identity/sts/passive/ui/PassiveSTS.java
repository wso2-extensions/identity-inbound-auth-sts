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
package org.wso2.carbon.identity.sts.passive.ui;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sts.passive.stub.types.RequestToken;
import org.wso2.carbon.identity.sts.passive.stub.types.ResponseToken;
import org.wso2.carbon.identity.sts.passive.ui.cache.SessionDataCache;
import org.wso2.carbon.identity.sts.passive.ui.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.sts.passive.ui.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.sts.passive.ui.client.IdentityPassiveSTSClient;
import org.wso2.carbon.identity.sts.passive.ui.dto.SessionDTO;
import org.wso2.carbon.identity.sts.passive.ui.util.PassiveSTSHttpServletRequestWrapper;
import org.wso2.carbon.identity.sts.passive.ui.util.PassiveSTSUtil;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.ui.CarbonUIUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AUTHENTICATED_USER;
import static org.wso2.carbon.identity.sts.passive.ui.PassiveRequestorConstants.ERROR_AUTHENTICATION;
import static org.wso2.carbon.identity.sts.passive.ui.PassiveRequestorConstants.ERROR_MSG_LOGOUT_WREPLY_MISMATCH;

public class PassiveSTS extends HttpServlet {

    private static final Log log = LogFactory.getLog(PassiveSTS.class);

    /**
     *
     */
    private static final long serialVersionUID = 1927253892844132565L;
    private static final String SESSION_DATA_KEY = "sessionDataKey";
    private static final String STS_ACTION_SIGNOUT = "wsignout1.0";
    private static final String STS_ACTION_SIGNIN = "wsignin1.0";

    private String stsRedirectPage = null;
    private String redirectHtmlFilePath = CarbonUtils.getCarbonHome() + File.separator + "repository"
            + File.separator + "resources" + File.separator + "identity" + File.separator + "pages" + File.separator +
            "sts_response.html";
    private static final String HTTP = "http";
    private static final String HTTPS = "https";
    private static final String PASSIVE_STS_CLIENT_TYPE = "passivests";
    private static final String PASSIVE_STS_W_REPLY_PROPERTY = "passiveSTSWReply";
    private static final String PASSIVE_STS_W_REPLY_LOGOUT_PROPERTY = "passiveSTSWReplyLogout";
    private static final String PASSIVE_STS_EP_URL = "/passivests";
    // Backward compatibility toggle can be wired via config later if needed.

    /**
     * This method reads Passive STS Html Redirect file content.
     * This should have been implemented in the backend but done in the front end to avoid API changes
     *
     * @return Passive STS Html Redirect Page File Content
     */
    private String readPassiveSTSHtmlRedirectPage() {
        FileInputStream fileInputStream = null;
        String fileContent = null;
        try {
            fileInputStream = new FileInputStream(new File(redirectHtmlFilePath));
            fileContent = new Scanner(fileInputStream, "UTF-8").useDelimiter("\\A").next();

            if (log.isDebugEnabled()) {
                log.debug("sts_response.html : " + fileContent);
            }

        } catch (FileNotFoundException e) {
            // The Passive STS Redirect HTML file is optional. When the file is not found, use the default page content.
            if (log.isDebugEnabled()) {
                log.debug("Passive STS Redirect HTML file not found in : " + redirectHtmlFilePath +
                        ". Default Redirect is used.");
            }
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    log.error("Error occurred when closing file input stream for sts_response.html", e);
                }
            }
        }

        if (StringUtils.isBlank(fileContent)) {
            fileContent = "<html>" +
                    "    <body>" +
                    "        <p>You are now redirected to $url ." +
                    "           If the redirection fails, please click the post button." +
                    "        </p>" +
                    "        <form method='post' action='$url'>" +
                    "        <p>" +
                    "            <!--$params-->" +
                    "            <!--$additionalParams-->" +
                    "            <button type='submit'>POST</button>" +
                    "       </p>" +
                    "       </form>" +
                    "        <script type='text/javascript'>" +
                    "            document.forms[0].submit();" +
                    "        </script>" +
                    "    </body>" +
                    "</html>";
        }

        // Adding parameters to the Passive STS HTML redirect page
        String parameters = "<input type=\"hidden\" name=\"wa\" value=\"$action\">" +
                "<input type=\"hidden\" name=\"wresult\" value=\"$result\">";

        if (StringUtils.isNotBlank(parameters)) {
            fileContent = fileContent.replace("<!--$params-->", parameters);
        }

        return fileContent;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String sessionDataKey = req.getParameter(SESSION_DATA_KEY);
        if (sessionDataKey != null) {
            handleResponseFromAuthenticationFramework(req, resp);
            FrameworkUtils.removeAuthenticationResultFromCache(sessionDataKey);
        } else if ("wsignout1.0".equals(getAttribute(req.getParameterMap(), PassiveRequestorConstants.ACTION))) {
            try {
                handleLogoutRequest(req, resp);
            } catch (PassiveSTSException e) {
                log.error("Error occurred while handling the Passive STS logout request.", e);
            }
        } else {
            try {
                handleAuthenticationRequest(req, resp);
            } catch (PassiveSTSException e) {
                log.error("Error occurred while handling the Passive STS authentication request.", e);
            }
        }
    }

    private void sendData(HttpServletResponse httpResp, ResponseToken respToken, String action,
                          String authenticatedIdPs)
            throws ServletException, IOException {

        if (StringUtils.isBlank(stsRedirectPage)) {
            // Read the Passive STS Html Redirect Page File Content
            stsRedirectPage = readPassiveSTSHtmlRedirectPage();
        }
        String finalPage = null;
        String htmlPage = stsRedirectPage;
        String pageWithReply = htmlPage.replace("$url", String.valueOf(respToken.getReplyTo()));

        String pageWithReplyAction = pageWithReply.replace("$action", Encode.forHtmlAttribute(String.valueOf(action)));
        String pageWithReplyActionResult = pageWithReplyAction.replace("$result",
                Encode.forHtmlAttribute(String.valueOf(respToken.getResults())));
        String pageWithReplyActionResultContext;
        if (respToken.getContext() != null) {
            pageWithReplyActionResultContext = pageWithReplyActionResult.replace(
                    PassiveRequestorConstants.PASSIVE_ADDITIONAL_PARAMETER,
                    PassiveRequestorConstants.PASSIVE_ADDITIONAL_PARAMETER + "<input type='hidden' name='wctx' value='"
                            + Encode.forHtmlAttribute(respToken.getContext()) + "'>");
        } else {
            pageWithReplyActionResultContext = pageWithReplyActionResult;
        }

        if (authenticatedIdPs == null || authenticatedIdPs.isEmpty()) {
            finalPage = pageWithReplyActionResultContext;
        } else {
            finalPage = pageWithReplyActionResultContext.replace(PassiveRequestorConstants.PASSIVE_ADDITIONAL_PARAMETER,
                    "<input type='hidden' name='AuthenticatedIdPs' value='" +
                            Encode.forHtmlAttribute(authenticatedIdPs) + "'>");
        }

        httpResp.setContentType("text/html; charset=UTF-8");
        PrintWriter out = httpResp.getWriter();
        out.print(finalPage);

        if (log.isDebugEnabled()) {
            log.debug("sts_response.html : " + finalPage);
        }
        return;
    }

    private String getAttribute(Map paramMap, String name) {
        if (paramMap.get(name) != null && paramMap.get(name) instanceof String[]) {
            return ((String[]) paramMap.get(name))[0];
        }
        return null;
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }

    private void sendSignOutCleanupRequests(HttpServletRequest request) {

        Set<String> wreplySet =
                (Set<String>) request.getSession().getAttribute(PassiveRequestorConstants.REPLY_TO);

        String hostNameVerificationEnabledProperty =
                IdentityUtil.getProperty(IdentityConstants.STS.PASSIVE_STS_SLO_HOST_NAME_VERIFICATION_ENABLED);
        boolean isHostNameVerificationEnabled = true;
        if ("false".equalsIgnoreCase(hostNameVerificationEnabledProperty)) {
            isHostNameVerificationEnabled = false;
        }

        if (CollectionUtils.isNotEmpty(wreplySet)) {

            List<String> malformedWreplyURLs = new ArrayList<>();

            for (String wreply : wreplySet) {
                // Skipping the realm which initiated the logout request
                if (wreply.equals(getAttribute(request.getParameterMap(), PassiveRequestorConstants.REPLY_TO))) {
                    continue;
                }

                try {
                    URL url;
                    if (wreply.contains("?")) {
                        url = new URL(wreply + "&" + PassiveRequestorConstants.ACTION + "=" + PassiveRequestorConstants.
                                REQUESTOR_ACTION_CLEANUP_10);
                    } else {
                        url = new URL(wreply + "?" + PassiveRequestorConstants.ACTION + "=" + PassiveRequestorConstants.
                                REQUESTOR_ACTION_CLEANUP_10);
                    }
                    if (HTTP.equals(url.getProtocol())) {
                        HttpURLConnection httpUrlConnection = (HttpURLConnection) url.openConnection();
                        int responseCode = httpUrlConnection.getResponseCode();
                        composeLogsFromResponse(responseCode, wreply, httpUrlConnection.getResponseMessage());
                    } else if (HTTPS.equals(url.getProtocol())) {
                        HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) url.openConnection();
                        if (!isHostNameVerificationEnabled) {
                            httpsUrlConnection.setHostnameVerifier(new HostnameVerifier() {
                                @Override
                                public boolean verify(String s, SSLSession sslSession) {
                                    return true;
                                }
                            });
                        }
                        int responseCode = httpsUrlConnection.getResponseCode();
                        composeLogsFromResponse(responseCode, wreply, httpsUrlConnection.getResponseMessage());
                    }
                } catch (MalformedURLException e) {
                    log.warn("A malformed URL: " + wreply + " found in the wreply values set. wreply values should be" +
                            " URLs.");
                    malformedWreplyURLs.add(wreply);
                } catch (IOException e) {
                    log.error("Error sending logout cleanup request to " + wreply, e);
                }
            }

            // Removing malformed URLs from the wreply values set.
            for (String malformedWreplyURL : malformedWreplyURLs) {
                wreplySet.remove(malformedWreplyURL);
                log.warn("Removing malformed URL: " + malformedWreplyURL + " from wreply values set.");
            }
        }
    }

    /**
     * Composes logs from response code.
     *
     * @param responseCode response Code
     * @param wreply wreply url
     * @param message response message
     */
    private void composeLogsFromResponse(int responseCode, String wreply, String message) {

        if (responseCode == HttpsURLConnection.HTTP_OK || responseCode == HttpsURLConnection.
                HTTP_MOVED_TEMP) {
            if (log.isDebugEnabled()) {
                log.debug("Single logout cleanup request sent to " + wreply + " returned with " +
                        message);
            }
        } else {
            log.warn("Failed single logout response from " + wreply + " with status " +
                    message);
        }
    }

    /**
     * persists wreply urls in a session.
     *
     * @param responseToken response token
     * @param session session
     */
    private void persistWreply(ResponseToken responseToken, HttpSession session) {

        Set<String> wreplySet = (Set<String>) session.getAttribute(PassiveRequestorConstants.REPLY_TO);
        if (wreplySet == null) {
            wreplySet = new HashSet<>();
            session.setAttribute(PassiveRequestorConstants.REPLY_TO, wreplySet);
        }
        wreplySet.add(responseToken.getReplyTo());
    }

    private void sendToAuthenticationFramework(HttpServletRequest request, HttpServletResponse response,
                                               String sessionDataKey, SessionDTO sessionDTO, String tenantDomain)
            throws IOException, PassiveSTSException {

        String commonAuthURL;
        try {
            commonAuthURL = ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new PassiveSTSException("Error occurred while building the commonauth URL during login.", e);
        }

        String selfPath;
        try {
            selfPath = ServiceURLBuilder.create().addPath(PASSIVE_STS_EP_URL).build().getRelativeInternalURL();
        } catch (URLBuilderException e) {
            throw new PassiveSTSException("Error occurred while building commonauth caller path URL during login.", e);
        }

        //Authentication context keeps data which should be sent to commonAuth endpoint
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.setRelyingParty(sessionDTO.getRealm());
        authenticationRequest.setCommonAuthCallerPath(selfPath);
        authenticationRequest.setForceAuth(false);
        authenticationRequest.setRequestQueryParams(request.getParameterMap());
        if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            authenticationRequest.setTenantDomain(tenantDomain);
        }

        //adding headers in out going request to authentication request context
        for (Enumeration e = request.getHeaderNames(); e.hasMoreElements(); ) {
            String headerName = e.nextElement().toString();
            authenticationRequest.addHeader(headerName, request.getHeader(headerName));
        }

        //Add authenticationRequest cache entry to cache
        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry(authenticationRequest);
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);
        StringBuilder queryStringBuilder = new StringBuilder();
        queryStringBuilder.append("?").
                append(FrameworkConstants.SESSION_DATA_KEY).
                                  append("=").
                                  append(sessionDataKey).
                                  append("&").
                                  append(FrameworkConstants.RequestParams.TYPE).
                                  append("=").
                                  append(FrameworkConstants.PASSIVE_STS);
        response.sendRedirect(commonAuthURL + queryStringBuilder.toString());
    }

    private void handleResponseFromAuthenticationFramework(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String sessionDataKey = request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
        SessionDTO sessionDTO = getSessionDataFromCache(sessionDataKey);
        AuthenticationResult authnResult = getAuthenticationResultFromCache(sessionDataKey);

        if (sessionDTO != null && authnResult != null) {

            if (authnResult.isAuthenticated()) {
                process(request, response, sessionDTO, authnResult);
            } else {
                // TODO how to send back the authentication failure to client.
                //for now user will be redirected back to the framework
                // According to ws-federation-1.2-spec; 'wtrealm' will not be sent in the Passive STS Logout Request.

                if (StringUtils.isNotBlank(sessionDTO.getReplyTo())) {
                    response.sendRedirect(sessionDTO.getReplyTo());
                } else {
                    sendToRetryPage(request, response);
                }
            }
        } else {
            sendToRetryPage(request, response);
        }
    }

    private void process(HttpServletRequest request, HttpServletResponse response,
                         SessionDTO sessionDTO, AuthenticationResult authnResult) throws ServletException, IOException {

        regenerateSession(request);
        HttpSession session = request.getSession();

        session.removeAttribute(PassiveRequestorConstants.PASSIVE_REQ_ATTR_MAP);

        RequestToken reqToken = new RequestToken();

        Map<ClaimMapping, String> attrMap = authnResult.getSubject().getUserAttributes();
        StringBuilder buffer = null;

        if (MapUtils.isNotEmpty(attrMap)) {
            buffer = new StringBuilder();
            for (Iterator<Entry<ClaimMapping, String>> iterator = attrMap.entrySet().iterator(); iterator
                    .hasNext(); ) {
                Entry<ClaimMapping, String> entry = iterator.next();
                buffer.append("{" + entry.getKey().getRemoteClaim().getClaimUri() + "|" + entry.getValue() + "}#CODE#");
            }
        }

        reqToken.setAction(sessionDTO.getAction());
        if (buffer != null) {
            reqToken.setAttributes(buffer.toString());
        } else {
            reqToken.setAttributes(sessionDTO.getAttributes());
        }
        reqToken.setContext(sessionDTO.getContext());
        reqToken.setReplyTo(sessionDTO.getReplyTo());
        reqToken.setPseudo(sessionDTO.getPseudo());
        reqToken.setRealm(sessionDTO.getRealm());
        reqToken.setRequest(sessionDTO.getRequest());
        reqToken.setRequestPointer(sessionDTO.getRequestPointer());
        reqToken.setPolicy(sessionDTO.getPolicy());
        reqToken.setPseudo(session.getId());
        reqToken.setUserName(authnResult.getSubject().getAuthenticatedSubjectIdentifier());
        if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            reqToken.setTenantDomain(sessionDTO.getTenantDomain());
        }

        String serverURL = CarbonUIUtil.getServerURL(session.getServletContext(), session);
        ConfigurationContext configContext =
                (ConfigurationContext) session.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);

        IdentityPassiveSTSClient passiveSTSClient = new IdentityPassiveSTSClient(serverURL, configContext);

        ResponseToken respToken;
        // Adding the AuthenticatedUser as a threadLocal property in order to avoid API changes related to RequestToken
        try {
            IdentityUtil.threadLocalProperties.get().put(AUTHENTICATED_USER, authnResult.getSubject());
            respToken = passiveSTSClient.getResponse(reqToken);
        } finally {
            // Remove thread local variable
            IdentityUtil.threadLocalProperties.get().remove(AUTHENTICATED_USER);
        }

        if (respToken != null && respToken.getResults() != null) {
            persistWreply(respToken, request.getSession());
            sendData(response, respToken, reqToken.getAction(),
                     authnResult.getAuthenticatedIdPs());
        }
    }


    private void handleLogoutRequest(HttpServletRequest request, HttpServletResponse response)
            throws IOException, PassiveSTSException {

        // Validate the logout url if the logout wreply validation is enabled.
        if (Boolean.parseBoolean(IdentityUtil.getProperty(
                IdentityConstants.STS.PASSIVE_STS_LOGOUT_WREPLY_VALIDATION))) {
            try {
                validateLogoutURL(request);
            } catch (PassiveSTSException e) {
                log.error(e.getMessage());
                PassiveSTSUtil.sendToErrorPage(request, response,
                        ERROR_AUTHENTICATION, ERROR_MSG_LOGOUT_WREPLY_MISMATCH);
                return;
            }
        }

        // wreply parameter is optional for the logout request. So we are setting that value from the service
        // provider configuration in case it is not available in the request.
        if (StringUtils.isBlank(getAttribute(request.getParameterMap(), PassiveRequestorConstants.REPLY_TO)) &&
                StringUtils.isNotBlank(getAttribute(request.getParameterMap(), PassiveRequestorConstants.REALM))) {
            request = new PassiveSTSHttpServletRequestWrapper(request);
            setWReplyUrl((PassiveSTSHttpServletRequestWrapper) request);
        }

        /**
         * todo: Framework logout response is not handled now (https://wso2.org/jira/browse/IDENTITY-4501).
         * todo: Once it's being fixed, sign out clean up requests should be initiated asynchronously from that point.
         */
        sendSignOutCleanupRequests(request);

        try {
            sendFrameworkForLogout(request, response);
        } catch (ServletException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while sending the logout request", e);
            }
        }
    }

    /**
     * Validate the wreply url sent in the logout request with the configured logout wreply url.
     * The user is redirected to an error page upon validation failure.
     *
     * @param request   Logout request.
     * @throws PassiveSTSException Error in logout url validation.
     */
    private void validateLogoutURL(HttpServletRequest request)
            throws PassiveSTSException {

        String wreplyFromReq = getAttribute(request.getParameterMap(), PassiveRequestorConstants.REPLY_TO);
        if (StringUtils.isNotBlank(wreplyFromReq)) {
            String configuredWreply = getConfiguredWreplyLogoutUrl(request);
            if (!wreplyFromReq.equals(configuredWreply)) {
                throw new PassiveSTSException("Provided wreply URL in the request does not match the configured " +
                        "wreply logout url.");
            }
        }
    }

    /**
     * Retrieve the configured wreply logout url from the service provider.
     *
     * @param request   Logout request.
     * @return          Wreply logout url configured in the service provider.
     * @throws PassiveSTSException Errors in retrieving the configured wreply url.
     */
    private String getConfiguredWreplyLogoutUrl(HttpServletRequest request) throws PassiveSTSException {

        String wtrealm = getAttribute(request.getParameterMap(), PassiveRequestorConstants.REALM);
        if (StringUtils.isBlank(wtrealm)) {
            throw new PassiveSTSException("Missing parameter wtrealm in request.");
        }
        String tenantDomain = getTenantDomain(request);
        ServiceProvider serviceProvider = getServiceProvider(wtrealm, tenantDomain);
        Property[] properties = getInboundAuthConfigPropertiesFromSP(serviceProvider);
        if (ArrayUtils.isNotEmpty(properties)) {
            String wreplyUrl = null;
            for (Property property : properties) {
                if (PASSIVE_STS_W_REPLY_LOGOUT_PROPERTY.equalsIgnoreCase(property.getName())) {
                    return property.getValue();
                } else if (PASSIVE_STS_W_REPLY_PROPERTY.equalsIgnoreCase(property.getName())) {
                    wreplyUrl = property.getValue();
                }
            }
            // If the logout specific wreply url is not set, fallback to the wreply url.
            if (StringUtils.isNotBlank(wreplyUrl)) {
                return wreplyUrl;
            }
        }
        return null;
    }

    /**
     * Get the passive sts inbound authentication config properties from the service provider.
     *
     * @param serviceProvider   Service provider.
     * @return                  Passive STS inbound authentication config properties.
     */
    private Property[] getInboundAuthConfigPropertiesFromSP(ServiceProvider serviceProvider) {

        InboundAuthenticationRequestConfig[] inboundAuthenticationConfigs =
                serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
        if (inboundAuthenticationConfigs != null) {
            for (InboundAuthenticationRequestConfig inboundAuthenticationConfig : inboundAuthenticationConfigs) {
                if (PASSIVE_STS_CLIENT_TYPE.equals(inboundAuthenticationConfig.getInboundAuthType())) {
                    return inboundAuthenticationConfig.getProperties();
                }
            }
        }
        return null;
    }

    /**
     * Get the passive sts service provider for the given realm.
     *
     * @param wtrealm       Realm of the service provider.
     * @param tenantDomain  Tenant domain of the service provider.
     * @return              Passive STS Service provider.
     * @throws PassiveSTSException  Errors when getting the service provider.
     */
    private ServiceProvider getServiceProvider(String wtrealm, String tenantDomain) throws PassiveSTSException {

        try {
            ServiceProvider serviceProvider = ApplicationManagementService.getInstance()
                    .getServiceProviderByClientId(wtrealm, PASSIVE_STS_CLIENT_TYPE, tenantDomain);
            if (serviceProvider == null || IdentityApplicationConstants.DEFAULT_SP_CONFIG.equals(serviceProvider
                    .getApplicationName())) {
                throw new PassiveSTSException("Service provider for wtrealm: "  + wtrealm + " in tenant: "
                        + tenantDomain + " is null or the default service provider.");
            }
            return serviceProvider;
        } catch (IdentityApplicationManagementException e) {
            throw new PassiveSTSException("Failed to retrieve service provider for wtrealm: " + wtrealm +
                    " in tenant: " + tenantDomain);
        }
    }

    /**
     * Get tenant domain.
     * @param request   HTTP request.
     * @return          Tenant domain.
     */
    private String getTenantDomain(HttpServletRequest request) {

        String tenantDomain;
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        } else {
            tenantDomain = getAttribute(request.getParameterMap(), MultitenantConstants.TENANT_DOMAIN);
        }
        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    /**
     * This method set the wreply value to the request from the service provider configuration
     *
     * @param request logout request
     */
    private void setWReplyUrl(PassiveSTSHttpServletRequestWrapper request) {

        String wtrealm = getAttribute(request.getParameterMap(), PassiveRequestorConstants.REALM);
        String tenantDomain;
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        } else {
            tenantDomain = getAttribute(request.getParameterMap(), MultitenantConstants.TENANT_DOMAIN);
        }
        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        ServiceProvider serviceProvider;
        try {
            serviceProvider = ApplicationManagementService.getInstance().getServiceProviderByClientId(wtrealm,
                    PASSIVE_STS_CLIENT_TYPE, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            log.error("Failed to retrieve service provider configuration for wtrealm: " + wtrealm + " in tenant: "
                    + tenantDomain);
            return;
        }

        if (serviceProvider == null || IdentityApplicationConstants.DEFAULT_SP_CONFIG.equals(serviceProvider
                .getApplicationName())) {
            return;
        }

        InboundAuthenticationRequestConfig[] inboundAuthenticationConfigs =
                serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
        if (inboundAuthenticationConfigs != null) {
            loop:
            for (InboundAuthenticationRequestConfig inboundAuthenticationConfig : inboundAuthenticationConfigs) {
                if (PASSIVE_STS_CLIENT_TYPE.equals(inboundAuthenticationConfig.getInboundAuthType())) {
                    Property[] properties = inboundAuthenticationConfig.getProperties();
                    if (ArrayUtils.isNotEmpty(properties)) {
                        String wreplyUrl = null;
                        for (Property property : properties) {
                            if (PASSIVE_STS_W_REPLY_LOGOUT_PROPERTY.equalsIgnoreCase(property.getName())) {
                                request.addParameter(PassiveRequestorConstants.REPLY_TO, property.getValue());
                                break loop;
                            } else if (PASSIVE_STS_W_REPLY_PROPERTY.equalsIgnoreCase(property.getName())) {
                                wreplyUrl = property.getValue();
                            }
                        }
                        // If the logout specific wreply url is not set, fallback to the wreply url.
                        if (StringUtils.isNotBlank(wreplyUrl)) {
                            request.addParameter(PassiveRequestorConstants.REPLY_TO, wreplyUrl);
                            break;
                        }
                    }
                }
            }
        }
    }

    private void sendFrameworkForLogout(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, PassiveSTSException {

        Map<String, String[]> paramMap = request.getParameterMap();
        String tenantDomain = resolveTenantDomain(paramMap);
        SessionDTO sessionDTO = buildSessionDTO(paramMap, tenantDomain, request.getQueryString());

        String sessionDataKey = UUIDGenerator.generateUUID();
        addSessionDataToCache(sessionDataKey, sessionDTO);
        String commonAuthURL;
        try {
            commonAuthURL = ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new PassiveSTSException("Error occurred while building the commonauth URL during logout.", e);
        }

        String selfPath;
        try {
            selfPath = ServiceURLBuilder.create().addPath(PASSIVE_STS_EP_URL).build().getRelativeInternalURL();
        } catch (URLBuilderException e) {
            throw new PassiveSTSException("Error occurred while building commonauth caller path URL during logout.", e);
        }

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.addRequestQueryParam(FrameworkConstants.RequestParams.LOGOUT,
                new String[]{Boolean.TRUE.toString()});
        authenticationRequest.setRequestQueryParams(request.getParameterMap());
        authenticationRequest.setCommonAuthCallerPath(selfPath);
        authenticationRequest.appendRequestQueryParams(request.getParameterMap());
        if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            authenticationRequest.setTenantDomain(tenantDomain);
        }
        // According to ws-federation-1.2-spec; 'wtrealm' will not be sent in the Passive STS Logout Request.
        if (sessionDTO.getRealm() == null || sessionDTO.getRealm().trim().length() == 0) {
            authenticationRequest.setRelyingParty(new String());
        }
        for (Enumeration e = request.getHeaderNames(); e.hasMoreElements(); ) {
            String headerName = e.nextElement().toString();
            authenticationRequest.addHeader(headerName, request.getHeader(headerName));
        }

        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry
                (authenticationRequest);
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);
        String queryParams = "?" + FrameworkConstants.SESSION_DATA_KEY + "=" + URLEncoder.encode(sessionDataKey, "UTF-8")
                + "&" + FrameworkConstants.RequestParams.TYPE + "=" + FrameworkConstants.PASSIVE_STS;

        response.sendRedirect(commonAuthURL + queryParams);

    }

    private void handleAuthenticationRequest(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException, PassiveSTSException {

        Map<String, String[]> paramMap = request.getParameterMap();
        String tenantDomain = resolveTenantDomain(paramMap);
        SessionDTO sessionDTO = buildSessionDTO(paramMap, tenantDomain, request.getQueryString());

        String sessionDataKey = UUIDGenerator.generateUUID();
        addSessionDataToCache(sessionDataKey, sessionDTO);

        sendToAuthenticationFramework(request, response, sessionDataKey, sessionDTO, tenantDomain);
    }

    private String resolveTenantDomain(Map<String, String[]> paramMap) {

        String tenantDomain;
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            if (log.isDebugEnabled()) {
                log.debug("Tenant domain from context: " + tenantDomain);
            }
            return tenantDomain;
        }

        tenantDomain = getAttribute(paramMap, MultitenantConstants.TENANT_DOMAIN);
        if (log.isDebugEnabled()) {
            log.debug("Tenant domain from query param: " + tenantDomain);
        }
        return tenantDomain;
    }

    private SessionDTO buildSessionDTO(Map<String, String[]> paramMap, String tenantDomain, String queryString) {

        SessionDTO sessionDTO = new SessionDTO();
        sessionDTO.setAction(getAttribute(paramMap, PassiveRequestorConstants.ACTION));
        sessionDTO.setAttributes(getAttribute(paramMap, PassiveRequestorConstants.ATTRIBUTE));
        sessionDTO.setContext(getAttribute(paramMap, PassiveRequestorConstants.CONTEXT));
        sessionDTO.setReplyTo(getAttribute(paramMap, PassiveRequestorConstants.REPLY_TO));
        sessionDTO.setPseudo(getAttribute(paramMap, PassiveRequestorConstants.PSEUDO));
        sessionDTO.setRealm(getAttribute(paramMap, PassiveRequestorConstants.REALM));
        sessionDTO.setRequest(getAttribute(paramMap, PassiveRequestorConstants.REQUEST));
        sessionDTO.setRequestPointer(getAttribute(paramMap, PassiveRequestorConstants.REQUEST_POINTER));
        sessionDTO.setPolicy(getAttribute(paramMap, PassiveRequestorConstants.POLCY));
        sessionDTO.setTenantDomain(tenantDomain);
        sessionDTO.setReqQueryString(queryString);

        return sessionDTO;
    }

    private void addSessionDataToCache(String sessionDataKey, SessionDTO sessionDTO) {
        SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
        SessionDataCacheEntry cacheEntry = new SessionDataCacheEntry();
        cacheEntry.setSessionDTO(sessionDTO);
        SessionDataCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private SessionDTO getSessionDataFromCache(String sessionDataKey) {
        SessionDTO sessionDTO = null;
        SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
        SessionDataCacheEntry cacheEntry = SessionDataCache.getInstance().getValueFromCache(cacheKey);

        if (cacheEntry != null) {
            sessionDTO = cacheEntry.getSessionDTO();
        } else {
            log.error("SessionDTO does not exist. Probably due to cache timeout");
        }

        return sessionDTO;
    }

    private AuthenticationResult getAuthenticationResultFromCache(String sessionDataKey) {
        AuthenticationResult authResult = null;
        AuthenticationResultCacheEntry authResultCacheEntry = FrameworkUtils.getAuthenticationResultFromCache(sessionDataKey);
        if (authResultCacheEntry != null) {
            authResult = authResultCacheEntry.getResult();
        } else {
            log.error("AuthenticationResult does not exist. Probably due to cache timeout");
        }

        return authResult;
    }

    private void sendToRetryPage(HttpServletRequest request, HttpServletResponse response) throws IOException {

        response.sendRedirect(PassiveSTSUtil.getRetryUrl());
    }

    /**
     * Regenerate session after successful authentication
     *
     * @param request HttpServelet Request instance
     */
    private void regenerateSession(HttpServletRequest request) {

        HttpSession oldSession = request.getSession();

        Enumeration attrNames = oldSession.getAttributeNames();
        Properties props = new Properties();

        while (attrNames != null && attrNames.hasMoreElements()) {
            String key = (String) attrNames.nextElement();
            props.put(key, oldSession.getAttribute(key));
        }

        oldSession.invalidate();
        HttpSession newSession = request.getSession(true);
        attrNames = props.keys();

        while (attrNames != null && attrNames.hasMoreElements()) {
            String key = (String) attrNames.nextElement();
            newSession.setAttribute(key, props.get(key));
        }
    }
}
