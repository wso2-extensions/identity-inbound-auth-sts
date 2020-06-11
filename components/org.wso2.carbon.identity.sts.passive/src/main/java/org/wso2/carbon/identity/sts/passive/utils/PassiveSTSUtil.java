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

package org.wso2.carbon.identity.sts.passive.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.ws.security.sts.provider.STSException;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.wso2.carbon.identity.sts.passive.PassiveRequestorConstants;
import org.wso2.carbon.identity.sts.passive.RequestToken;

public class PassiveSTSUtil {

    private static final Log log = LogFactory.getLog(PassiveSTSUtil.class);

    public static String extractTokenType(RequestToken token) throws STSException {

        String tokenType = null;
        String wreq = token.getRequest();
        if (wreq != null && wreq.trim().length() > 0) {
            OMElement rootElement;
            try {
                rootElement = AXIOMUtil.stringToOM(wreq);
            } catch (XMLStreamException e) {
                throw new STSException("RequestFailed", e);
            }
            OMElement tokenElement = rootElement.getFirstChildWithName(new QName(
                    PassiveRequestorConstants.WS_TRUST_200512_NS_URI, PassiveRequestorConstants.TOKEN_TYPE_LOCAL));
            tokenType = tokenElement.getText();

        }
        return tokenType;
    }
}

