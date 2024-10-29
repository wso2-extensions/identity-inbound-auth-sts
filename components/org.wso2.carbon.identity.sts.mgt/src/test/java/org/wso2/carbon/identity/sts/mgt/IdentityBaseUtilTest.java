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
package org.wso2.carbon.identity.sts.mgt;

import org.apache.neethi.Policy;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.sts.mgt.base.IdentityBaseUtil;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;

/**
 * Test class for IdentityBaseUtil test cases
 */
public class IdentityBaseUtilTest {

    @Test
    public void testGetDefaultRampartConfig() throws Exception {

        // Mock ServerConfiguration
        try (MockedStatic<ServerConfiguration> serverConfiguration = mockStatic(ServerConfiguration.class)) {

            ServerConfiguration mockServerConfiguration = mock(ServerConfiguration.class);
            serverConfiguration.when(ServerConfiguration::getInstance).thenReturn(mockServerConfiguration);
            when(mockServerConfiguration.getFirstProperty(anyString())).thenReturn("mockedValue");

            Policy policy = IdentityBaseUtil.getDefaultRampartConfig();
            assertNotNull(policy);
            assertNotNull(policy.getFirstPolicyComponent());
        }
    }
}
