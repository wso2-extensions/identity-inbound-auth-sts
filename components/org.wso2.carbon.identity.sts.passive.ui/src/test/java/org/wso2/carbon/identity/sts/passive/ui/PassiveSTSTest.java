/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sts.passive.ui;

import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
@WithRealmService
@WithAxisConfiguration
public class PassiveSTSTest {

    PassiveSTS passiveSTS;

    @BeforeMethod
    public void setUp() throws Exception {
        passiveSTS = new PassiveSTS();
    }

    @DataProvider(name = "DoPostData")
    public Object[][] doPostData() {
        return new Object[][]{
                // wa value
                {PassiveRequestorConstants.REQUESTOR_ACTION_SIGNOUT_10},
                {"testAction"}
        };
    }

    @Test(dataProvider = "DoPostData")
    public void testDoPost(String waValue) throws Exception {

        // This test is written based on the issue IDENTITY-6883.
        // This is expected not to throw a MalformedURLException.
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        HttpSession session = Mockito.mock(HttpSession.class);
        Map<String, String[]> parameters = new HashMap<>();
        Set<String> wreplySet = new HashSet<>();
        String wreply = "http://localhost:8080/PassiveSTSSampleApp";
        Enumeration<String> headers = new Enumeration<String>() {
            @Override
            public boolean hasMoreElements() {
                return false;
            }

            @Override
            public String nextElement() {
                return null;
            }
        };
        parameters.put(PassiveRequestorConstants.ACTION, new String[]{waValue});
        parameters.put(PassiveRequestorConstants.REPLY_TO, new String[]{wreply});
        wreplySet.add("MalformedURL");
        wreplySet.add(wreply);
        when(request.getParameterMap()).thenReturn(parameters);
        when(session.getAttribute(anyString())).thenReturn(wreplySet);
        when(request.getSession()).thenReturn(session);
        when(request.getHeaderNames()).thenReturn(headers);

        passiveSTS.doPost(request, response);
        assertTrue(true, "No MalformedURLException occurred.");
    }

}
