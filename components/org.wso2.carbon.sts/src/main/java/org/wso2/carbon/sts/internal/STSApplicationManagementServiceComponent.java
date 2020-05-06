/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.sts.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.consent.mgt.core.ConsentManager;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.sts.listener.STSApplicationMgtListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

/**
 * OSGI Service component for Application (aka Service Provider) management.
 */
@Component(
        name = "sts.application.management.component",
        immediate = true
)
public class STSApplicationManagementServiceComponent {

    private static Log log = LogFactory.getLog(STSApplicationManagementServiceComponent.class);
    private static BundleContext bundleContext;

    @Activate
    protected void activate(ComponentContext context) {

        try {
            bundleContext = context.getBundleContext();
            ServiceRegistration stsApplicationMgtListener = bundleContext.registerService(ApplicationMgtListener
                    .class.getName(), new STSApplicationMgtListener(), null);
            if (stsApplicationMgtListener != null) {
                if (log.isDebugEnabled()) {
                    log.debug("STS - ApplicationMgtListener registered.");
                }
            } else {
                log.error("STS - ApplicationMgtListener could not be registered.");
            }

            if (log.isDebugEnabled()) {
                log.debug("Identity ApplicationManagementComponent bundle is activated");
            }
        } catch (Exception e) {
            log.error("Error while activating STSApplicationManagementComponent bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Identity STSApplicationManagementComponent bundle is deactivated");
        }
    }

    @Reference(
            name = "registry.service",
            service = RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
    protected void setRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in STSApplicationManagementComponent bundle");
        }
        ApplicationManagementServiceComponentHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in STSApplicationManagementComponent bundle");
        }
        ApplicationManagementServiceComponentHolder.getInstance().setRegistryService(null);
    }

    @Reference(
            name = "user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        ApplicationManagementServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service");
        }
        ApplicationManagementServiceComponentHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "configuration.context.service",
            service = ConfigurationContextService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationContextService"
    )
    protected void setConfigurationContextService(ConfigurationContextService configContextService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Configuration Context Service");
        }
        ApplicationManagementServiceComponentHolder.getInstance().setConfigContextService(configContextService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configContextService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Configuration Context Service");
        }
        ApplicationManagementServiceComponentHolder.getInstance().setConfigContextService(null);
    }

    @Reference(
            name = "application.mgt.authenticator",
            service = AbstractInboundAuthenticatorConfig.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetInboundAuthenticatorConfig"
    )
    protected void setInboundAuthenticatorConfig(AbstractInboundAuthenticatorConfig authenticator) {

        ApplicationManagementServiceComponentHolder.addInboundAuthenticatorConfig(authenticator);
    }

    protected void unsetInboundAuthenticatorConfig(AbstractInboundAuthenticatorConfig authenticator) {

        ApplicationManagementServiceComponentHolder.removeInboundAuthenticatorConfig(authenticator.getName());
    }

    @Reference(
            name = "consent.mgt.service",
            service = ConsentManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConsentMgtService"
    )
    protected void setConsentMgtService(ConsentManager consentManager) {

        ApplicationManagementServiceComponentHolder.getInstance().setConsentManager(consentManager);
    }

    protected void unsetConsentMgtService(ConsentManager consentManager) {

        ApplicationManagementServiceComponentHolder.getInstance().setConsentManager(null);
    }
}
