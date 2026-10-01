/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.sts.passive.utils;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for {@link RequestProcessorUtil}.
 */
public class RequestProcessorUtilTest {

    private static final String WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static final String WSU_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String WSSE_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSA_NS = "http://www.w3.org/2005/08/addressing";

    /**
     * One of the prefix assignments JAXB produces: ns2 = WS-Trust, ns3 = wsu, ns4 = wsse.
     */
    @Test
    public void testChangeNamespacesWithOneGeneratedPrefixOrder() {

        String response = buildResponse("ns2", WST_NS, "ns3", WSU_NS, "ns4", WSSE_NS);
        assertPrefixesResolved(RequestProcessorUtil.changeNamespaces(response));
    }

    /**
     * The same namespaces bound to different generated prefixes. JAXB does not assign ns1, ns2, ... in a
     * guaranteed order, so the positional replacement used earlier mislabeled these. This is the
     * regression being covered.
     */
    @Test
    public void testChangeNamespacesWithAnotherGeneratedPrefixOrder() {

        String response = buildResponse("ns3", WST_NS, "ns2", WSU_NS, "ns5", WSSE_NS);
        assertPrefixesResolved(RequestProcessorUtil.changeNamespaces(response));
    }

    /**
     * Prefixes that JAXB did not generate must be preserved, so that the signature over the issued
     * assertion stays valid. The same goes for text that merely looks like a generated prefix.
     */
    @Test
    public void testChangeNamespacesPreservesNonGeneratedPrefixesAndContent() {

        String response = "<ns2:RequestSecurityTokenResponse xmlns:ns2=\"" + WST_NS + "\">" +
                "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "<saml2:NameID>admin@dns2.example.com</saml2:NameID>" +
                "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>" +
                "</saml2:Assertion></ns2:RequestSecurityTokenResponse>";

        String result = RequestProcessorUtil.changeNamespaces(response);

        assertEquals(result, "<wst:RequestSecurityTokenResponse xmlns:wst=\"" + WST_NS + "\">" +
                "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "<saml2:NameID>admin@dns2.example.com</saml2:NameID>" +
                "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>" +
                "</saml2:Assertion></wst:RequestSecurityTokenResponse>");
    }

    /**
     * Namespaces other than WS-Trust, wsu and wsse keep the prefix JAXB generated for them, which is what
     * the shape of the RSTR actually produced by CXF looks like: WS-Trust is the default namespace and the
     * addressing namespace is declared but never used.
     */
    @Test
    public void testChangeNamespacesLeavesUnmappedNamespacesUntouched() {

        String response = "<RequestSecurityTokenResponseCollection xmlns=\"" + WST_NS + "\" " +
                "xmlns:ns2=\"" + WSU_NS + "\" xmlns:ns3=\"" + WSSE_NS + "\" xmlns:ns4=\"" + WSA_NS + "\">" +
                "<RequestSecurityTokenResponse><Lifetime>" +
                "<ns2:Created>2026-01-01T00:00:00Z</ns2:Created></Lifetime>" +
                "<RequestedAttachedReference><ns3:SecurityTokenReference/></RequestedAttachedReference>" +
                "</RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection>";

        String result = RequestProcessorUtil.changeNamespaces(response);

        assertTrue(result.contains("xmlns:wsu=\"" + WSU_NS + "\""));
        assertTrue(result.contains("<wsu:Created>"));
        assertTrue(result.contains("xmlns:wsse=\"" + WSSE_NS + "\""));
        assertTrue(result.contains("<wsse:SecurityTokenReference/>"));
        // The addressing namespace is not one this class labels, so its prefix is left alone.
        assertTrue(result.contains("xmlns:ns4=\"" + WSA_NS + "\""));
    }

    /**
     * A generated prefix must not be renamed when its canonical prefix is already bound to another
     * namespace in the response.
     */
    @Test
    public void testChangeNamespacesSkipsRenameOnPrefixCollision() {

        String response = "<ns2:RequestSecurityTokenResponse xmlns:ns2=\"" + WST_NS + "\" " +
                "xmlns:wst=\"urn:some:other:namespace\"/>";

        assertEquals(RequestProcessorUtil.changeNamespaces(response), response);
    }

    @Test
    public void testChangeNamespacesWithEmptyResponse() {

        assertEquals(RequestProcessorUtil.changeNamespaces(""), "");
        assertEquals(RequestProcessorUtil.changeNamespaces(null), null);
    }

    private String buildResponse(String wstPrefix, String wstNs, String wsuPrefix, String wsuNs,
                                 String wssePrefix, String wsseNs) {

        return "<" + wstPrefix + ":RequestSecurityTokenResponseCollection xmlns:" + wstPrefix + "=\"" + wstNs +
                "\" xmlns:" + wsuPrefix + "=\"" + wsuNs + "\" xmlns:" + wssePrefix + "=\"" + wsseNs + "\">" +
                "<" + wstPrefix + ":RequestSecurityTokenResponse>" +
                "<" + wstPrefix + ":Lifetime>" +
                "<" + wsuPrefix + ":Created>2025-01-01T00:00:00Z</" + wsuPrefix + ":Created>" +
                "<" + wsuPrefix + ":Expires>2025-01-01T01:00:00Z</" + wsuPrefix + ":Expires>" +
                "</" + wstPrefix + ":Lifetime>" +
                "<" + wstPrefix + ":RequestedAttachedReference>" +
                "<" + wssePrefix + ":SecurityTokenReference>" +
                "<" + wssePrefix + ":KeyIdentifier " + wssePrefix + ":ValueType=\"SAMLID\">_id</" +
                wssePrefix + ":KeyIdentifier>" +
                "</" + wssePrefix + ":SecurityTokenReference>" +
                "</" + wstPrefix + ":RequestedAttachedReference>" +
                "</" + wstPrefix + ":RequestSecurityTokenResponse>" +
                "</" + wstPrefix + ":RequestSecurityTokenResponseCollection>";
    }

    private void assertPrefixesResolved(String result) {

        assertTrue(result.contains("xmlns:wst=\"" + WST_NS + "\""));
        assertTrue(result.contains("xmlns:wsu=\"" + WSU_NS + "\""));
        assertTrue(result.contains("xmlns:wsse=\"" + WSSE_NS + "\""));

        assertTrue(result.contains("<wst:RequestSecurityTokenResponseCollection"));
        assertTrue(result.contains("<wst:Lifetime>"));
        assertTrue(result.contains("<wsu:Created>"));
        assertTrue(result.contains("<wsu:Expires>"));
        assertTrue(result.contains("<wsse:SecurityTokenReference>"));
        assertTrue(result.contains("wsse:ValueType=\"SAMLID\""));

        assertFalse(result.contains("ns2:"));
        assertFalse(result.contains("ns3:"));
        assertFalse(result.contains("ns5:"));
    }
}
