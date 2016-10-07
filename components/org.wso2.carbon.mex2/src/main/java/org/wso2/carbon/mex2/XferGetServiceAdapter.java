/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.mex2;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.xfer.WSTransferException;
import org.wso2.xfer.WSTransferOperations;


public class XferGetServiceAdapter implements WSTransferOperations {

    private static final Log logger = LogFactory.getLog(XferGetServiceAdapter.class);

    MexGetService service;

    public XferGetServiceAdapter() {
        service = new MexGetService();
    }

    public OMElement get(OMElement request) throws WSTransferException {

        try {
            if (request.getFirstElement() != null) {
                return service.get(request);
            } else {
                return service.get2(request);
            }
        } catch (Exception e) {
            logger.error("Error while processing the WSTransfer request", e);
            throw new RuntimeException(e);
        }
    }

    public OMElement delete(OMElement headers) throws WSTransferException {
        throw new UnsupportedOperationException("delete() not supported");
    }

    public OMElement put(OMElement headers, OMElement resource) throws WSTransferException {
        throw new UnsupportedOperationException("put() not supported");
    }


}
