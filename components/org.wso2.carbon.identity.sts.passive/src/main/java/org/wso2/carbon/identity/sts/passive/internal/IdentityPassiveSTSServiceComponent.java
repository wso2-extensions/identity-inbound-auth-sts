/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.sts.passive.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(
         name = "identity.passive.sts.component", 
         immediate = true)
public class IdentityPassiveSTSServiceComponent {

    private static final Log log = LogFactory.getLog(IdentityPassiveSTSServiceComponent.class);

    private static RealmService userRealmService = null;

    private static RegistryService registryService;

    /**
     */
    public IdentityPassiveSTSServiceComponent() {
    }

    /**
     * @return
     */
    public static RealmService getRealmService() {
        return userRealmService;
    }

    /**
     * @param userRealmDelegating
     */
    @Reference(
             name = "user.realmservice.default", 
             service = org.wso2.carbon.user.core.service.RealmService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetRealmService")
    protected void setRealmService(RealmService realm) {
        if (log.isDebugEnabled()) {
            log.info("DelegatingUserRealm set in Identity Provider bundle");
        }
        userRealmService = realm;
    }

    public static RegistryService getRegistryervice() {
        return registryService;
    }

    public static Registry getGovernanceSystemRegistry() throws RegistryException {
        return (Registry) CarbonContext.getThreadLocalCarbonContext().getRegistry(RegistryType.SYSTEM_GOVERNANCE);
    }

    public static Registry getConfigSystemRegistry() throws RegistryException {
        return (Registry) CarbonContext.getThreadLocalCarbonContext().getRegistry(RegistryType.SYSTEM_CONFIGURATION);
    }

    /**
     * @param ctxt
     */
    @Activate
    protected void activate(ComponentContext ctxt) {
    }

    /**
     * @param userRealmDelegating
     */
    protected void unsetRealmService(RealmService realm) {
        if (log.isDebugEnabled()) {
            log.info("DelegatingUserRealm set in Identity Provider bundle");
        }
    }

    @Reference(
             name = "registry.service", 
             service = org.wso2.carbon.registry.core.service.RegistryService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetRegistryService")
    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Passive STS bundle");
        }
        IdentityPassiveSTSServiceComponent.registryService = registryService;
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in Passive STS bundle");
        }
        IdentityPassiveSTSServiceComponent.registryService = null;
    }
}

