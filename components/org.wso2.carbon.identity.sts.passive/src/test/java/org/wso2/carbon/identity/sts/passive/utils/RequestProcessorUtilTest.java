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

import org.apache.cxf.sts.QNameConstants;
import org.apache.cxf.sts.STSConstants;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseCollectionType;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseType;
import org.apache.cxf.ws.security.sts.provider.model.RequestedSecurityTokenType;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertSame;
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

    private static final String REALM = "urn:wsfed:repro";
    private static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

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

    @Test(description = "Removing AppliesTo before marshalling keeps the signed assertion, its audience " +
            "restriction and its signature intact.")
    public void testRemoveAppliesToKeepsSignedAssertionValid() throws Exception {

        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        RequestSecurityTokenResponseCollectionType withAppliesTo =
                buildSignedResponseCollection(signedAssertion(keyPair), RequestProcessorUtil.createAppliesToElement(REALM));
        String unchanged = marshal(withAppliesTo);
        assertTrue(unchanged.contains("AppliesTo"), "AppliesTo should be written when it is not removed.");
        assertTrue(isSignatureValid(unchanged, keyPair.getPublic()));

        RequestSecurityTokenResponseCollectionType withoutAppliesTo =
                buildSignedResponseCollection(signedAssertion(keyPair), RequestProcessorUtil.createAppliesToElement(REALM));
        RequestProcessorUtil.removeAppliesTo(withoutAppliesTo);
        String result = marshal(withoutAppliesTo);

        assertFalse(result.contains("AppliesTo"), "AppliesTo should not be written to the response.");
        assertTrue(result.contains(REALM + "</saml2:Audience>"), "The audience restriction should be kept.");
        assertTrue(result.contains("RequestedSecurityToken"), "The requested security token should be kept.");
        assertTrue(isSignatureValid(result, keyPair.getPublic()), "The assertion signature should stay valid.");
    }

    @Test(description = "Only the AppliesTo item is removed and the other items keep their order.")
    public void testRemoveAppliesToLeavesOtherItemsUntouched() throws Exception {

        Object tokenType = QNameConstants.WS_TRUST_FACTORY.createTokenType("urn:token-type");
        Object appliesTo = RequestProcessorUtil.createAppliesToElement(REALM);
        Object lifetime = QNameConstants.WS_TRUST_FACTORY.createLifetime(
                QNameConstants.WS_TRUST_FACTORY.createLifetimeType());
        RequestSecurityTokenResponseCollectionType collection =
                buildResponseCollection(tokenType, appliesTo, lifetime);

        RequestProcessorUtil.removeAppliesTo(collection);

        List<Object> items = collection.getRequestSecurityTokenResponse().get(0).getAny();
        assertEquals(items.size(), 2);
        assertSame(items.get(0), tokenType);
        assertSame(items.get(1), lifetime);
    }

    @DataProvider(name = "policyNamespaces")
    public Object[][] policyNamespaces() {

        return new Object[][]{{STSConstants.WSP_NS}, {STSConstants.WSP_NS_04}, {STSConstants.WSP_NS_06}};
    }

    @Test(dataProvider = "policyNamespaces",
            description = "AppliesTo is removed in every WS-Policy namespace that CXF accepts.")
    public void testRemoveAppliesToInPolicyNamespaces(String namespace) throws Exception {

        RequestSecurityTokenResponseCollectionType collection =
                buildResponseCollection(element(namespace, "wsp:AppliesTo"));

        RequestProcessorUtil.removeAppliesTo(collection);

        assertTrue(collection.getRequestSecurityTokenResponse().get(0).getAny().isEmpty());
    }

    @Test(description = "AppliesTo wrapped in a JAXBElement is also removed.")
    public void testRemoveAppliesToAsJaxbElement() {

        RequestSecurityTokenResponseCollectionType collection = buildResponseCollection(
                new JAXBElement<>(new QName(STSConstants.WSP_NS, "AppliesTo"), String.class, REALM));

        RequestProcessorUtil.removeAppliesTo(collection);

        assertTrue(collection.getRequestSecurityTokenResponse().get(0).getAny().isEmpty());
    }

    @Test(description = "Elements that are not a WS-Policy AppliesTo are kept.")
    public void testRemoveAppliesToKeepsOtherElements() throws Exception {

        Element otherNamespace = element("urn:other", "o:AppliesTo");
        Element otherPolicyElement = element(STSConstants.WSP_NS, "wsp:Policy");
        RequestSecurityTokenResponseCollectionType collection =
                buildResponseCollection(otherNamespace, otherPolicyElement);

        RequestProcessorUtil.removeAppliesTo(collection);

        assertEquals(collection.getRequestSecurityTokenResponse().get(0).getAny().size(), 2);
    }

    @Test(description = "Null and empty responses are handled without errors.")
    public void testRemoveAppliesToWithEmptyResponses() {

        RequestProcessorUtil.removeAppliesTo(null);

        RequestSecurityTokenResponseCollectionType collection = new RequestSecurityTokenResponseCollectionType();
        RequestProcessorUtil.removeAppliesTo(collection);
        collection.getRequestSecurityTokenResponse().add(null);
        collection.getRequestSecurityTokenResponse().add(new RequestSecurityTokenResponseType());
        RequestProcessorUtil.removeAppliesTo(collection);

        assertEquals(collection.getRequestSecurityTokenResponse().size(), 2);
    }

    @DataProvider(name = "preserveAudienceRestrictionValues")
    public Object[][] preserveAudienceRestrictionValues() {

        return new Object[][]{
                {null, true},
                {"", true},
                {"   ", true},
                {"true", true},
                {"TRUE", true},
                {" true ", true},
                {"false", false},
                {"False", false},
                {"invalid", false}
        };
    }

    @Test(dataProvider = "preserveAudienceRestrictionValues",
            description = "The audience restriction is preserved by default and can be turned off explicitly.")
    public void testIsAudienceRestrictionPreserved(String configuredValue, boolean expected) {

        assertEquals(RequestProcessorUtil.isAudienceRestrictionPreserved(configuredValue), expected);
    }

    private RequestSecurityTokenResponseCollectionType buildResponseCollection(Object... items) {

        RequestSecurityTokenResponseType response = new RequestSecurityTokenResponseType();
        response.getAny().addAll(Arrays.asList(items));
        RequestSecurityTokenResponseCollectionType collection = new RequestSecurityTokenResponseCollectionType();
        collection.getRequestSecurityTokenResponse().add(response);
        return collection;
    }

    private RequestSecurityTokenResponseCollectionType buildSignedResponseCollection(Element signedAssertion,
                                                                                     Element appliesTo) {

        RequestedSecurityTokenType requestedToken =
                QNameConstants.WS_TRUST_FACTORY.createRequestedSecurityTokenType();
        requestedToken.setAny(signedAssertion);
        return buildResponseCollection(QNameConstants.WS_TRUST_FACTORY.createTokenType("urn:token-type"),
                QNameConstants.WS_TRUST_FACTORY.createRequestedSecurityToken(requestedToken), appliesTo);
    }

    private Element element(String namespace, String qualifiedName) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document document = factory.newDocumentBuilder().newDocument();
        Element element = document.createElementNS(namespace, qualifiedName);
        document.appendChild(element);
        return element;
    }

    /**
     * Builds and signs a SAML 2.0 style assertion. The attribute value contains characters that are escaped when
     * serialized, so that a change in the serialized form would break the signature.
     */
    private Element signedAssertion(KeyPair keyPair) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document document = factory.newDocumentBuilder().parse(new ByteArrayInputStream((
                "<saml2:Assertion xmlns:saml2=\"" + SAML2_NS + "\" ID=\"_assertion\" Version=\"2.0\">" +
                "<saml2:Issuer>localhost</saml2:Issuer>" +
                "<saml2:Conditions><saml2:AudienceRestriction><saml2:Audience>" + REALM +
                "</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>" +
                "<saml2:AttributeStatement><saml2:Attribute Name=\"note\"><saml2:AttributeValue>" +
                "a &amp; b &lt; c \"quoted\"</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement>" +
                "</saml2:Assertion>").getBytes(StandardCharsets.UTF_8)));
        Element assertion = document.getDocumentElement();
        assertion.setIdAttribute("ID", true);

        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        Reference reference = signatureFactory.newReference("#_assertion",
                signatureFactory.newDigestMethod(DigestMethod.SHA256, null),
                Arrays.asList(signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        signatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (TransformParameterSpec) null)),
                null, null);
        SignedInfo signedInfo = signatureFactory.newSignedInfo(
                signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        (C14NMethodParameterSpec) null),
                signatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
                Collections.singletonList(reference));
        signatureFactory.newXMLSignature(signedInfo, null)
                .sign(new DOMSignContext(keyPair.getPrivate(), assertion));
        return assertion;
    }

    private String marshal(RequestSecurityTokenResponseCollectionType collection) throws Exception {

        StringWriter writer = new StringWriter();
        Marshaller marshaller =
                JAXBContext.newInstance(RequestSecurityTokenResponseCollectionType.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.FALSE);
        marshaller.marshal(
                QNameConstants.WS_TRUST_FACTORY.createRequestSecurityTokenResponseCollection(collection), writer);
        return RequestProcessorUtil.changeNamespaces(writer.toString());
    }

    private boolean isSignatureValid(String response, PublicKey publicKey) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document document = factory.newDocumentBuilder()
                .parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
        Element assertion = (Element) document.getElementsByTagNameNS(SAML2_NS, "Assertion").item(0);
        assertion.setIdAttribute("ID", true);
        Element signature = (Element) assertion.getElementsByTagNameNS(DSIG_NS, "Signature").item(0);
        DOMValidateContext context = new DOMValidateContext(publicKey, signature);
        return XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context).validate(context);
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
