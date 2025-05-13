/*
 * Copyright (c) 2020-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.sts.common.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSPasswordCallback;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sts.common.SecurityConfigParams;
import org.wso2.carbon.identity.sts.common.UserCredentialRetriever;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.security.SecurityConfigException;
import org.wso2.carbon.security.SecurityConstants;
import org.wso2.carbon.security.SecurityServiceHolder;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.security.KeyStore;

import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * The password callback handler to be used to enable UsernameToken
 * authentication for services.
 */
public class ServicePasswordCallbackHandler implements CallbackHandler {
    private static final Log log = LogFactory.getLog(ServicePasswordCallbackHandler.class);

    private static final String TENANT_DOMAIN_SEPARATOR = "@";
    private static final String INCLUDE_USER_STORE_DOMAIN_IN_USERNAME = "SecurityTokenService.LocalSubjectIdentifier" +
            ".IncludeUserStoreDomain";
    private static final String INCLUDE_TENANT_DOMAIN_IN_USERNAME = "SecurityTokenService.LocalSubjectIdentifier" +
            ".IncludeTenantDomain";

    private String serviceGroupId = null;
    private String serviceId = null;
    private Registry registry = null;
    private UserRealm realm = null;
    private SecurityConfigParams configParams;
    private final boolean includeUserStoreDomainInUsername;
    private final boolean includeTenantInUsername;

    //todo there's a API change here. apparently only security component uses this. If not, change the invocations accordingly.
    public ServicePasswordCallbackHandler(SecurityConfigParams configParams, String serviceGroupId,
                                          String serviceId,
                                          Registry registry, UserRealm realm)
            throws RegistryException, SecurityConfigException {

        this.registry = registry;
        this.serviceId = serviceId;
        this.serviceGroupId = serviceGroupId;
        this.realm = realm;
        this.configParams = configParams;
        IdentityUtil.populateProperties();
        // If the property is not available, default value is true.
        this.includeUserStoreDomainInUsername = IdentityUtil.getProperty(INCLUDE_USER_STORE_DOMAIN_IN_USERNAME) == null
                || Boolean.parseBoolean(IdentityUtil.getProperty(INCLUDE_USER_STORE_DOMAIN_IN_USERNAME));
        // If the property is not available, default value is false.
        this.includeTenantInUsername = Boolean.parseBoolean(IdentityUtil.getProperty(INCLUDE_TENANT_DOMAIN_IN_USERNAME));
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        try {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof WSPasswordCallback) {
                    WSPasswordCallback passwordCallback = (WSPasswordCallback) callbacks[i];

                    String username = passwordCallback.getIdentifer();
                    String receivedPasswd = null;
                    switch (passwordCallback.getUsage()) {

                        case WSPasswordCallback.SIGNATURE:
                        case WSPasswordCallback.DECRYPT:
                            String password = getPrivateKeyPassword(username);
                            if (password == null) {
                                throw new UnsupportedCallbackException(callbacks[i],
                                        "User not available " + "in a trusted store");
                            }

                            passwordCallback.setPassword(password);

                            break;
                        case WSPasswordCallback.KERBEROS_TOKEN:
                            passwordCallback.setPassword(getServicePrincipalPassword());
                            break;
                        case WSPasswordCallback.USERNAME_TOKEN_UNKNOWN:

                            receivedPasswd = passwordCallback.getPassword();
                            try {
                                if (receivedPasswd != null
                                        && this.authenticateUser(username, receivedPasswd)) {
                                    username = applyLocalSubjectIdentifierConfigs(username);
                                    passwordCallback.setIdentifier(username);
                                } else {
                                    throw new UnsupportedCallbackException(callbacks[i], "check failed");
                                }
                            } catch (Exception e) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Error when authenticating user : " + username + ", password provided : "
                                            + StringUtils.isNotEmpty(receivedPasswd), e);
                                }
                                throw new UnsupportedCallbackException(callbacks[i],
                                        "Check failed : System error");
                            }

                            break;

                        case WSPasswordCallback.USERNAME_TOKEN:
                            // In username token scenario, if user sends the digested password, callback handler needs to provide plain text password.
                            // We get plain text password through UserCredentialRetriever interface, which is implemented by custom user store managers.
                            // we expect username with domain name if user resides in a secondary user store, eg, WSO2.Test/fooUser.
                            // Additionally, secondary user stores needs to implement UserCredentialRetriever interface too
                            UserCredentialRetriever userCredentialRetriever;
                            String storedPassword = null;
                            String domainName = IdentityUtil.extractDomainFromName(username);
                            if (UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(domainName)) {
                                if (realm.getUserStoreManager() instanceof UserCredentialRetriever) {
                                    userCredentialRetriever = (UserCredentialRetriever) realm.getUserStoreManager();
                                    storedPassword = userCredentialRetriever.getPassword(username);
                                } else {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Can not set user password in callback because primary userstore class" +
                                                " has not implemented UserCredentialRetriever interface.");
                                    }
                                }
                            } else {
                                if (realm.getUserStoreManager().getSecondaryUserStoreManager(domainName) instanceof UserCredentialRetriever) {
                                    userCredentialRetriever = (UserCredentialRetriever) realm.getUserStoreManager().getSecondaryUserStoreManager(domainName);
                                    storedPassword = userCredentialRetriever.getPassword(UserCoreUtil.removeDomainFromName(username));
                                } else {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Can not set user password in callback because secondary userstore " +
                                                "for domain:" + domainName + " has not implemented UserCredentialRetriever interface.");
                                    }
                                }
                            }
                            if (storedPassword != null) {
                                try {
                                    if (this.authenticateUser(username, storedPassword)) {
                                        // do nothing things are fine
                                    } else {
                                        if (log.isDebugEnabled()) {
                                            log.debug("User is not authorized!");
                                        }
                                        throw new UnsupportedCallbackException(callbacks[i], "check failed");
                                    }
                                } catch (Exception e) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Error when authenticating user : " + username + ", password provided : "
                                                + StringUtils.isNotEmpty(receivedPasswd), e);
                                    }
                                    throw new UnsupportedCallbackException(callbacks[i], "Check failed : System error");
                                }
                                passwordCallback.setPassword(storedPassword);
                                break;
                            }
                        default:

                            /*
                             * When the password is null WS4J reports an error
                             * saying no password available for the user. But its
                             * better if we simply report authentication failure
                             * Therefore setting the password to be the empty string
                             * in this situation.
                             */

                            passwordCallback.setPassword(receivedPasswd);
                            break;

                    }

                } else {
                    throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
                }
            }
        } catch (UnsupportedCallbackException | IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in handling ServicePasswordCallbackHandler", e); //logging invlaid passwords and attempts
                throw e;
            }
            throw e;
        } catch (UserStoreException | SecurityConfigException e) {
            log.error("Error in handling ServicePasswordCallbackHandler", e);
            throw new UnsupportedCallbackException(null, e.getMessage());
        } catch (Exception e) {
            log.error("Error in handling ServicePasswordCallbackHandler", e);
            //can't build an unsupported exception.
            throw new UnsupportedCallbackException(null, e.getMessage());
        }
    }

    /**
     * Apply local subject identifier configurations to the username.
     *
     * @param username Username to be processed.
     * @return Username with local subject identifier configurations applied.
     * @throws UserStoreException {@link UserStoreException}
     */
    private String applyLocalSubjectIdentifierConfigs(String username) throws UserStoreException {

        String processedUsername;
        if (includeTenantInUsername) {
            processedUsername = getUsernameWithTenantDomain(username);
            if (log.isDebugEnabled()) {
                log.debug("Updating username with tenant domain. Updated username: " + processedUsername);
            }
        } else {
            processedUsername = MultitenantUtils.getTenantAwareUsername(username);
            if (log.isDebugEnabled()) {
                log.debug("Removed tenant domain from the username. Updated username: " + processedUsername);
            }
        }

        if (includeUserStoreDomainInUsername) {
            String domainName = UserCoreUtil.getDomainFromThreadLocal();
            processedUsername = IdentityUtil.addDomainToName(processedUsername, domainName);
            if (log.isDebugEnabled()) {
                log.debug("Updating username with user store domain. Updated username: " + processedUsername);
            }
        } else {
            processedUsername = UserCoreUtil.removeDomainFromName(processedUsername);
            if (log.isDebugEnabled()) {
                log.debug("Removed user store domain from the username. Updated username is: " + processedUsername);
            }
        }
        return processedUsername;
    }

    /**
     * Get the username with the tenant domain appended.
     * @param username Username to be processed.
     * @return Username with the tenant domain appended.
     * @throws UserStoreException {@link UserStoreException}
     */
    private String getUsernameWithTenantDomain(String username) throws UserStoreException {

        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        if (StringUtils.isBlank(tenantDomain) || (SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain) &&
                !StringUtils.contains(username, SUPER_TENANT_DOMAIN_NAME))) {
            // If the tenant domain cannot be determined using the username, use the tenant domain of the service
            // provider
            return getServiceTenantDomainAppendedUser(username);
        }

        if (log.isDebugEnabled()) {
            log.debug("Tenant domain can be determined using the username. Hence appending the tenant domain to the " +
                    "tenant-aware username. Username: " + username + ", Tenant domain: " + tenantDomain);
        }
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        return tenantAwareUsername + TENANT_DOMAIN_SEPARATOR + tenantDomain;
    }


    private String getServicePrincipalPassword()
            throws SecurityConfigException {

        String password = configParams.getServerPrincipalPassword();
        if (password != null) {
            if (configParams.isServerPrincipalPasswordEncrypted()) {
                password = getDecryptedPassword(password);
            }
            return password;
        } else {
            String msg = "Service principal password param not found";
            log.error(msg);
            throw new SecurityConfigException(msg);
        }
    }

    private String getDecryptedPassword(String encryptedString) throws SecurityConfigException {

        CryptoUtil cryptoUtil = CryptoUtil.getDefaultCryptoUtil();
        try {
            return new String(cryptoUtil.base64DecodeAndDecrypt(encryptedString));
        } catch (CryptoException e) {
            String msg = "Unable to decode and decrypt password string.";
            log.error(msg, e);
            throw new SecurityConfigException(msg, e);
        }
    }

    public boolean authenticateUser(String user, String password) throws Exception {

        boolean isAuthenticated = false;
        boolean isAuthorized = false;

        try {
            // Before validating the tenant domain in the user's name against the tenant where service is deployed,
            // there is one scenario which needs to be handled separately. User's name in the request may arrive
            // without a tenant domain but expects to be validated against the service deployed tenant. For example,
            // this is the valid usecase when the application is non-SaaS. Therefore, the user is appended with the
            // tenant domain in which the service is deployed, if the tenant domain is not specified.
            String tenantDomain = MultitenantUtils.getTenantDomain(user);
            if (StringUtils.isBlank(tenantDomain) || (SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain) && !StringUtils
                    .contains(user, SUPER_TENANT_DOMAIN_NAME))) {
                user = getServiceTenantDomainAppendedUser(user);
            }

            // Verify whether user is in same tenant that service has been deployed.
            if (realm.getUserStoreManager().getTenantId() !=
                    SecurityServiceHolder.getRealmService().getTenantManager().getTenantId(MultitenantUtils.getTenantDomain(user))) {
                if (log.isDebugEnabled()) {
                    log.debug("User : " + user + " trying access service which is deployed in different tenant domain");
                }
                return false;
            }

            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(user);

            isAuthenticated = realm.getUserStoreManager().authenticate(
                    tenantAwareUserName, password);

            if (isAuthenticated) {

                int index = tenantAwareUserName.indexOf("/");
                if (index < 0) {
                    String domain = UserCoreUtil.getDomainFromThreadLocal();
                    if (domain != null) {
                        tenantAwareUserName = domain + "/" + tenantAwareUserName;
                    }
                }

                isAuthorized = realm.getAuthorizationManager()
                        .isUserAuthorized(tenantAwareUserName,
                                serviceGroupId + "/" + serviceId,
                                UserCoreConstants.INVOKE_SERVICE_PERMISSION);
                if (!isAuthorized) {
                    if (log.isDebugEnabled()) {
                        log.debug("Authorization failure for user : " + tenantAwareUserName);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failure for user : " + tenantAwareUserName);
                }
            }

            return isAuthorized;
        } catch (Exception e) {
            log.error("Error in authenticating user.", e);
            throw e;
        }
    }

    private String getPrivateKeyPassword(String username) throws IOException, Exception {

        String password = null;
        int tenantId = ((UserRegistry) registry).getTenantId();
        UserRegistry govRegistry = SecurityServiceHolder.getRegistryService().
                getGovernanceSystemRegistry(tenantId);
        try {
            KeyStoreManager keyMan = KeyStoreManager.getInstance(tenantId);
            if (govRegistry.resourceExists(SecurityConstants.KEY_STORES)) {
                Collection collection = (Collection) govRegistry.get(SecurityConstants.KEY_STORES);
                String[] ks = collection.getChildren();

                for (int i = 0; i < ks.length; i++) {

                    String fullname = ks[i];
                    //get the primary keystore, only if it is super tenant.
                    if (tenantId == MultitenantConstants.SUPER_TENANT_ID && fullname
                            .equals(RegistryResources.SecurityManagement.PRIMARY_KEYSTORE_PHANTOM_RESOURCE)) {
                        KeyStore store = keyMan.getPrimaryKeyStore();
                        if (store.containsAlias(username)) {
                            password = keyMan.getPrimaryPrivateKeyPasssword();
                            break;
                        }
                    } else {
                        String name = fullname.substring(fullname.lastIndexOf("/") + 1);
                        KeyStore store = null;
                        //Not all the keystores encrypted using primary keystore password. So, some of the keystores will fail while loading
                        store = keyMan.getKeyStore(name);
                        if (log.isDebugEnabled()) {
                            log.debug("Load the keystore " + name);
                        }
                        if (store != null && store.containsAlias(username)) {
                            Resource resource = (Resource) govRegistry.get(ks[i]);
                            CryptoUtil cryptoUtil = CryptoUtil.getDefaultCryptoUtil();
                            String encryptedPassword = resource
                                    .getProperty(SecurityConstants.PROP_PRIVATE_KEY_PASS);
                            password = new String(cryptoUtil
                                    .base64DecodeAndDecrypt(encryptedPassword));
                            break;
                        }
                    }

                }
            }

            // If the custom keystore is configured check for the password within the custom keystore.
            String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
            String keyStoreName = IdentityKeyStoreResolver.getInstance()
                    .getKeyStoreName(tenantDomain, IdentityKeyStoreResolverConstants.InboundProtocol.WS_TRUST);
            if (KeyStoreUtil.isCustomKeyStore(keyStoreName)) {
                KeyStore keyStore = IdentityKeyStoreResolver.getInstance()
                        .getKeyStore(tenantDomain, IdentityKeyStoreResolverConstants.InboundProtocol.WS_TRUST);
                if (keyStore.containsAlias(username)) {
                    password = IdentityKeyStoreResolver.getInstance()
                            .getKeyStoreConfig(tenantDomain, IdentityKeyStoreResolverConstants.InboundProtocol.WS_TRUST,
                                    RegistryResources.SecurityManagement.CustomKeyStore.PROP_PASSWORD);
                }
            }
        } catch (IOException e) {
            log.error("Error when getting PrivateKeyPassword.", e);
            throw e;
        } catch (Exception e) {
            log.error("Error when getting PrivateKeyPassword.", e);
            throw e;
        }

        return password;
    }


    private String getServiceTenantDomainAppendedUser(String user) throws IdentityRuntimeException, UserStoreException {

        String tenantDomainFromServiceRealm = IdentityTenantUtil.getTenantDomain(realm.getUserStoreManager()
                .getTenantId());
        if (log.isDebugEnabled()) {
            log.debug(String.format("User: %s, does not contain the tenant domain in the username, thus " +
                    "considered as a user in the service tenant domain: %s", user, tenantDomainFromServiceRealm));
        }
        return user + TENANT_DOMAIN_SEPARATOR + tenantDomainFromServiceRealm;
    }
}
