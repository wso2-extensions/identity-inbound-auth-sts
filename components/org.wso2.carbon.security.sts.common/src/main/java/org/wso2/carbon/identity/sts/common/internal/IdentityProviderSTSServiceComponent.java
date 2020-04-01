/*
 * Copyright (c) 2004-2005, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.sts.common.internal;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.sts.common.identity.provider.IdentityAttributeService;
import org.wso2.carbon.identity.sts.common.identity.provider.IdentityAttributeServiceStore;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

@Component(
        name = "identity.provider.sts.component",
        immediate = true)
public class IdentityProviderSTSServiceComponent {

    private static final Log log = LogFactory.getLog(IdentityProviderSTSServiceComponent.class);

    private static ConfigurationContext configContext;

    private static RealmService realmService;

    private static RegistryService registryService;

    private static ApplicationManagementService applicationManagementService;

    /**
     */
    public IdentityProviderSTSServiceComponent() {

    }

    public static RealmService getRealmService() {

        return realmService;
    }

    /**
     * @param realmService
     */
    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.info("ReleamService is set in Identity Provider STS Service Bundle");
        }
        this.realmService = realmService;
    }

    /**
     * @return
     */
    public static ConfigurationContext getConfigContext() {

        return configContext;
    }

    public static RegistryService getRegistryService() {

        return registryService;
    }

    public static ApplicationManagementService getApplicationManagementService() {

        return applicationManagementService;
    }

    /**
     * @param registryService
     */
    @Reference(
            name = "registry.service",
            service = org.wso2.carbon.registry.core.service.RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService")
    protected void setRegistryService(RegistryService registryService) {

        this.registryService = registryService;
        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Identity Provider STS Service bundle");
        }
    }

    /**
     * @param ctxt
     */
    @Activate
    protected void activate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Identity Provider STS Service bundle is activated");
        }
    }

    /**
     * @param ctxt
     */
    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Identity Provider STS Service bundle is deactivated");
        }
    }

    /**
     * @param registryService
     */
    protected void unsetRegistryService(RegistryService registryService) {

        this.registryService = null;
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in Identity Provider STS Service bundle");
        }
    }

    @Reference(
            name = "identity.application.management.component",
            service = org.wso2.carbon.identity.application.mgt.ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationMgtService")
    protected void setApplicationMgtService(ApplicationManagementService applicationMgtService) {

        if (log.isDebugEnabled()) {
            log.debug((Object) "ApplicationManagementService set in Identity Provider STS Service bundle");
        }
        applicationManagementService = applicationMgtService;
    }

    protected void unsetApplicationMgtService(ApplicationManagementService applicationMgtService) {

        if (log.isDebugEnabled()) {
            log.debug((Object) "ApplicationManagementService unset in Identity Provider STS Service bundle");
        }
        applicationManagementService = null;
    }

    /**
     * @param userRealmDelegating
     */
    protected void unsetUserRealmDelegating(UserRealm userRealmDelegating) {

        if (log.isDebugEnabled()) {
            log.debug("DelegatingUserRealm set in Identity Provider STS Service bundle");
        }
    }

    /**
     * @param userRealmDefault
     */
    protected void unsetUserRealmDefault(UserRealm userRealmDefault) {

        if (log.isDebugEnabled()) {
            log.debug("DefaultUserRealm unset in Identity Provider STS Service bundle");
        }
    }

    /**
     * @param realmService
     */
    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("ReleamService is unset in Identity Provider STS Service Bundle");
        }
    }

    @Reference(
            name = "identity.attribute.service",
            service = org.wso2.carbon.identity.sts.common.identity.provider.IdentityAttributeService.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeAttributeService")
    protected void addAttributeService(IdentityAttributeService attributeService) {

        if (log.isDebugEnabled()) {
            log.debug("IdentityAttributeService added in Identity Provider STS Service bundle");
        }
        IdentityAttributeServiceStore.addAttributeService(attributeService);
    }

    /**
     * @param attributeService
     */
    protected void removeAttributeService(IdentityAttributeService attributeService) {

        if (log.isDebugEnabled()) {
            log.debug("IdentityAttributeService removed in Identity Provider STS Service bundle");
            IdentityAttributeServiceStore.removeAttributeService(attributeService);
        }
    }

    /**
     * @param contextService
     */
    @Reference(
            name = "config.context.service",
            service = org.wso2.carbon.utils.ConfigurationContextService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationContextService")
    protected void setConfigurationContextService(ConfigurationContextService contextService) {

        if (log.isDebugEnabled()) {
            log.debug("ConfigurationContextService set in Identity Provider STS Service bundle");
        }
        configContext = contextService.getServerConfigContext();
    }

    /**
     * @param contextService
     */
    protected void unsetConfigurationContextService(ConfigurationContextService contextService) {

        if (log.isDebugEnabled()) {
            log.debug("ConfigurationContextService unset in Identity Provider STS Service bundle");
        }
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }
}
