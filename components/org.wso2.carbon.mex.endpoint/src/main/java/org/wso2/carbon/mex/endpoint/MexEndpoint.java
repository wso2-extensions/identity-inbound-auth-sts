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
package org.wso2.carbon.mex.endpoint;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

@Path("/mex")
public class MexEndpoint {

    private static final Log log = LogFactory.getLog(MexEndpoint.class);


    @GET
    @Path("/get1")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/xml;charset=UTF-8")
    public Response getXSD2() {

        if (log.isDebugEnabled()) {
            log.debug("--------------- Mex XSD GET request3--------------------");
        }

        String reponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" elementFormDefault=\"qualified\" targetNamespace=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">\n" +
                "   <xs:element name=\"RequestSecurityToken\" type=\"trust:RequestSecurityTokenType\" />\n" +
                "   <xs:complexType name=\"RequestSecurityTokenType\">\n" +
                "      <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\n" +
                "         <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" processContents=\"lax\" />\n" +
                "      </xs:choice>\n" +
                "      <xs:attribute name=\"Context\" type=\"xs:anyURI\" use=\"optional\" />\n" +
                "      <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                "   </xs:complexType>\n" +
                "   <xs:element name=\"RequestSecurityTokenResponse\" type=\"trust:RequestSecurityTokenResponseType\" />\n" +
                "   <xs:complexType name=\"RequestSecurityTokenResponseType\">\n" +
                "      <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\n" +
                "         <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" processContents=\"lax\" />\n" +
                "      </xs:choice>\n" +
                "      <xs:attribute name=\"Context\" type=\"xs:anyURI\" use=\"optional\" />\n" +
                "      <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                "   </xs:complexType>\n" +
                "   <xs:element name=\"RequestSecurityTokenResponseCollection\" type=\"trust:RequestSecurityTokenResponseCollectionType\" />\n" +
                "   <xs:complexType name=\"RequestSecurityTokenResponseCollectionType\">\n" +
                "      <xs:sequence>\n" +
                "         <xs:element minOccurs=\"1\" maxOccurs=\"unbounded\" ref=\"trust:RequestSecurityTokenResponse\" />\n" +
                "      </xs:sequence>\n" +
                "      <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                "   </xs:complexType>\n" +
                "</xs:schema>";
        Response.ResponseBuilder responseBuilder = Response.status(200);
        responseBuilder.status(200);
        responseBuilder.entity(reponse);
        return responseBuilder.build();
    }

    @GET
    @Path("/get2")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/xml;charset=UTF-8")
    public Response getXSD1() {

        if (log.isDebugEnabled()) {
            log.debug("--------------- Mex XSD GET request2--------------------");
        }

        String reponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" elementFormDefault=\"qualified\" targetNamespace=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">\n" +
                "   <xs:element name=\"RequestSecurityToken\" type=\"wst:RequestSecurityTokenType\" />\n" +
                "   <xs:complexType name=\"RequestSecurityTokenType\">\n" +
                "      <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\n" +
                "         <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" processContents=\"lax\" />\n" +
                "      </xs:choice>\n" +
                "      <xs:attribute name=\"Context\" type=\"xs:anyURI\" use=\"optional\" />\n" +
                "      <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                "   </xs:complexType>\n" +
                "   <xs:element name=\"RequestSecurityTokenResponse\" type=\"wst:RequestSecurityTokenResponseType\" />\n" +
                "   <xs:complexType name=\"RequestSecurityTokenResponseType\">\n" +
                "      <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\n" +
                "         <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" processContents=\"lax\" />\n" +
                "      </xs:choice>\n" +
                "      <xs:attribute name=\"Context\" type=\"xs:anyURI\" use=\"optional\" />\n" +
                "      <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                "   </xs:complexType>\n" +
                "</xs:schema>";
        Response.ResponseBuilder responseBuilder = Response.status(200);
        responseBuilder.status(200);
        responseBuilder.entity(reponse);
        return responseBuilder.build();
    }

    @GET
    @Path("/get3")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/xml;charset=UTF-8")


    public Response getXSD0() {

        if (log.isDebugEnabled()) {
            log.debug("--------------- Mex XSD GET request1--------------------");
        }

        String reponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:tns=\"http://schemas.microsoft.com/Message\" elementFormDefault=\"qualified\" targetNamespace=\"http://schemas.microsoft.com/Message\">\n" +
                "   <xs:complexType name=\"MessageBody\">\n" +
                "      <xs:sequence>\n" +
                "         <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" />\n" +
                "      </xs:sequence>\n" +
                "   </xs:complexType>\n" +
                "</xs:schema>";
        Response.ResponseBuilder responseBuilder = Response.status(200);
        responseBuilder.status(200);
        responseBuilder.entity(reponse);
        return responseBuilder.build();
    }


}
