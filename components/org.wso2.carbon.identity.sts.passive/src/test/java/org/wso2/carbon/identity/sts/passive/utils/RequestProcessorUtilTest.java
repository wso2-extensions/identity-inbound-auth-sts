/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.sts.passive.utils;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseCollectionType;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseType;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for RequestProcessorUtil.
 */
public class RequestProcessorUtilTest {

    @Test
    public void testCreateAppliesToElement() {

        String realm = "urn:wsfed:repro";
        Element appliesTo = RequestProcessorUtil.createAppliesToElement(realm);

        assertNotNull(appliesTo, "AppliesTo element should not be null.");
        assertEquals(appliesTo.getLocalName(), "AppliesTo");
        assertEquals(appliesTo.getElementsByTagNameNS("*", "Address").item(0).getTextContent(), realm);
    }

    @Test
    public void testRemoveAppliesToFromResponseWithDOMElement() {

        RequestSecurityTokenResponseCollectionType collection = new RequestSecurityTokenResponseCollectionType();
        RequestSecurityTokenResponseType rstr = new RequestSecurityTokenResponseType();
        collection.getRequestSecurityTokenResponse().add(rstr);

        Element appliesTo = RequestProcessorUtil.createAppliesToElement("urn:wsfed:repro");
        Document doc = DOMUtils.getEmptyDocument();
        Element otherElement = doc.createElementNS("http://docs.oasis-open.org/ws-sx/ws-trust/200512", "TokenType");
        otherElement.setTextContent("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1");

        rstr.getAny().add(otherElement);
        rstr.getAny().add(appliesTo);

        assertEquals(rstr.getAny().size(), 2);

        RequestProcessorUtil.removeAppliesToFromResponse(collection);

        List<Object> remainingElements = rstr.getAny();
        assertEquals(remainingElements.size(), 1);
        assertEquals(remainingElements.get(0), otherElement);
    }

    @Test
    public void testRemoveAppliesToFromResponseWithJAXBElement() {

        RequestSecurityTokenResponseCollectionType collection = new RequestSecurityTokenResponseCollectionType();
        RequestSecurityTokenResponseType rstr = new RequestSecurityTokenResponseType();
        collection.getRequestSecurityTokenResponse().add(rstr);

        QName appliesToQName = new QName("http://www.w3.org/ns/ws-policy", "AppliesTo");
        JAXBElement<String> jaxbAppliesTo = new JAXBElement<>(appliesToQName, String.class, "urn:wsfed:repro");

        QName tokenTypeQName = new QName("http://docs.oasis-open.org/ws-sx/ws-trust/200512", "TokenType");
        JAXBElement<String> jaxbTokenType = new JAXBElement<>(tokenTypeQName, String.class, "saml-token");

        rstr.getAny().add(jaxbTokenType);
        rstr.getAny().add(jaxbAppliesTo);

        assertEquals(rstr.getAny().size(), 2);

        RequestProcessorUtil.removeAppliesToFromResponse(collection);

        List<Object> remainingElements = rstr.getAny();
        assertEquals(remainingElements.size(), 1);
        assertEquals(remainingElements.get(0), jaxbTokenType);
    }

    @Test
    public void testRemoveAppliesToFromResponseNullAndEmpty() {

        // Should not throw NullPointerException on null collection.
        RequestProcessorUtil.removeAppliesToFromResponse(null);

        // Should not throw exception on empty collection.
        RequestSecurityTokenResponseCollectionType emptyCollection = new RequestSecurityTokenResponseCollectionType();
        RequestProcessorUtil.removeAppliesToFromResponse(emptyCollection);

        // Should not throw exception on RSTR with null or empty getAny().
        RequestSecurityTokenResponseType rstr = new RequestSecurityTokenResponseType();
        emptyCollection.getRequestSecurityTokenResponse().add(rstr);
        RequestProcessorUtil.removeAppliesToFromResponse(emptyCollection);

        assertTrue(rstr.getAny().isEmpty());
    }

    @Test
    public void testRemoveAppliesToFromMultipleRSTRs() {

        RequestSecurityTokenResponseCollectionType collection = new RequestSecurityTokenResponseCollectionType();

        RequestSecurityTokenResponseType rstr1 = new RequestSecurityTokenResponseType();
        Element appliesTo1 = RequestProcessorUtil.createAppliesToElement("urn:realm:1");
        Document doc1 = DOMUtils.getEmptyDocument();
        Element token1 = doc1.createElement("Token1");
        rstr1.getAny().add(token1);
        rstr1.getAny().add(appliesTo1);

        RequestSecurityTokenResponseType rstr2 = new RequestSecurityTokenResponseType();
        Element appliesTo2 = RequestProcessorUtil.createAppliesToElement("urn:realm:2");
        Document doc2 = DOMUtils.getEmptyDocument();
        Element token2 = doc2.createElement("Token2");
        rstr2.getAny().add(appliesTo2);
        rstr2.getAny().add(token2);

        collection.getRequestSecurityTokenResponse().add(rstr1);
        collection.getRequestSecurityTokenResponse().add(rstr2);

        RequestProcessorUtil.removeAppliesToFromResponse(collection);

        assertEquals(rstr1.getAny().size(), 1);
        assertEquals(rstr1.getAny().get(0), token1);

        assertEquals(rstr2.getAny().size(), 1);
        assertEquals(rstr2.getAny().get(0), token2);
    }
}
