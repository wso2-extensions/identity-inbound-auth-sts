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
package org.wso2.carbon.identity.sts.passive.custom.provider;

import org.apache.cxf.sts.claims.ClaimsUtils;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.IdentityClaimManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.claim.Claim;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for CustomAttributeProvider.
 */
public class CustomAttributeProviderTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String CLAIM_URI = "http://wso2.org/claims/email";
    private static final String CLAIM_DISPLAY_TAG = "Email Address";
    private static final String CLAIM_URI_FRAGMENT = "email";
    private static final String CLAIM_NAMESPACE = "http://wso2.org/claims";

    /**
     * Subclass that bypasses the OSGi-dependent PrivilegedCarbonContext.
     */
    private static class TestableCustomAttributeProvider extends CustomAttributeProvider {

        @Override
        protected String getCurrentTenantDomain() {

            return TENANT_DOMAIN;
        }
    }

    private void setupClaimManager(MockedStatic<IdentityClaimManager> mockedClaimManager,
            MockedStatic<IdentityTenantUtil> mockedTenantUtil,
            Claim[] supportedClaims) throws IdentityException {

        UserRealm mockRealm = mock(UserRealm.class);
        mockedTenantUtil.when(() -> IdentityTenantUtil.getRealm(anyString(), any())).thenReturn(mockRealm);

        IdentityClaimManager mockIdentityClaimManager = mock(IdentityClaimManager.class);
        mockedClaimManager.when(IdentityClaimManager::getInstance).thenReturn(mockIdentityClaimManager);
        when(mockIdentityClaimManager.getAllSupportedClaims(anyString(), any(UserRealm.class)))
                .thenReturn(supportedClaims);
    }

    private TokenProviderParameters buildMockParams(String tokenType,
            ProcessedClaimCollection claims,
            MockedStatic<ClaimsUtils> mockedClaimsUtils) {

        TokenProviderParameters mockParams = mock(TokenProviderParameters.class);
        TokenRequirements mockTokenReqs = mock(TokenRequirements.class);
        when(mockParams.getTokenRequirements()).thenReturn(mockTokenReqs);
        when(mockTokenReqs.getTokenType()).thenReturn(tokenType);
        mockedClaimsUtils.when(() -> ClaimsUtils.processClaims(mockParams)).thenReturn(claims);
        return mockParams;
    }

    private ProcessedClaimCollection buildSingleClaimCollection(String claimUri) {

        ProcessedClaim processedClaim = new ProcessedClaim();
        processedClaim.setClaimType(claimUri);
        processedClaim.setValues(Collections.singletonList("test@example.com"));
        ProcessedClaimCollection collection = new ProcessedClaimCollection();
        collection.add(processedClaim);
        return collection;
    }

    @Test
    public void testGetStatement_claimDescriptionEnabled_usesDisplayTag() throws Exception {

        try (MockedStatic<IdentityClaimManager> mockedClaimManager = mockStatic(IdentityClaimManager.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ClaimsUtils> mockedClaimsUtils = mockStatic(ClaimsUtils.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            Claim supportedClaim = new Claim();
            supportedClaim.setClaimUri(CLAIM_URI);
            supportedClaim.setDisplayTag(CLAIM_DISPLAY_TAG);
            setupClaimManager(mockedClaimManager, mockedTenantUtil, new Claim[]{supportedClaim});

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.STS.PASSIVE_STS_ENABLE_CLAIM_DESCRIPTION_IN_ATTRIBUTE_NAME))
                    .thenReturn("true");

            ProcessedClaimCollection claims = buildSingleClaimCollection(CLAIM_URI);
            TokenProviderParameters mockParams = buildMockParams(
                    WSS4JConstants.WSS_SAML2_TOKEN_TYPE, claims, mockedClaimsUtils);

            AttributeStatementBean result = new TestableCustomAttributeProvider().getStatement(mockParams);

            assertNotNull(result);
            assertEquals(result.getSamlAttributes().size(), 1);
            AttributeBean attributeBean = result.getSamlAttributes().get(0);
            assertEquals(attributeBean.getSimpleName(), CLAIM_DISPLAY_TAG);
            // namespace is the full claim URI when display tag path is taken
            assertEquals(attributeBean.getQualifiedName(), CLAIM_URI);
        }
    }

    @Test
    public void testGetStatement_claimDescriptionDisabled_usesUriFragment() throws Exception {

        try (MockedStatic<IdentityClaimManager> mockedClaimManager = mockStatic(IdentityClaimManager.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ClaimsUtils> mockedClaimsUtils = mockStatic(ClaimsUtils.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            setupClaimManager(mockedClaimManager, mockedTenantUtil, new Claim[0]);

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.STS.PASSIVE_STS_ENABLE_CLAIM_DESCRIPTION_IN_ATTRIBUTE_NAME))
                    .thenReturn("false");

            ProcessedClaimCollection claims = buildSingleClaimCollection(CLAIM_URI);
            TokenProviderParameters mockParams = buildMockParams(
                    WSS4JConstants.WSS_SAML2_TOKEN_TYPE, claims, mockedClaimsUtils);

            AttributeStatementBean result = new TestableCustomAttributeProvider().getStatement(mockParams);

            assertNotNull(result);
            AttributeBean attributeBean = result.getSamlAttributes().get(0);
            assertEquals(attributeBean.getSimpleName(), CLAIM_URI_FRAGMENT);
            assertEquals(attributeBean.getQualifiedName(), CLAIM_NAMESPACE);
        }
    }

    @Test
    public void testGetStatement_claimDescriptionEnabled_claimNotInSupported_fallsBackToUriFragment()
            throws Exception {

        try (MockedStatic<IdentityClaimManager> mockedClaimManager = mockStatic(IdentityClaimManager.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ClaimsUtils> mockedClaimsUtils = mockStatic(ClaimsUtils.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            // supportedClaims contains a different claim URI than the one being processed
            Claim otherClaim = new Claim();
            otherClaim.setClaimUri("http://wso2.org/claims/username");
            otherClaim.setDisplayTag("Username");
            setupClaimManager(mockedClaimManager, mockedTenantUtil, new Claim[]{otherClaim});

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.STS.PASSIVE_STS_ENABLE_CLAIM_DESCRIPTION_IN_ATTRIBUTE_NAME))
                    .thenReturn("true");

            ProcessedClaimCollection claims = buildSingleClaimCollection(CLAIM_URI);
            TokenProviderParameters mockParams = buildMockParams(
                    WSS4JConstants.WSS_SAML2_TOKEN_TYPE, claims, mockedClaimsUtils);

            AttributeStatementBean result = new TestableCustomAttributeProvider().getStatement(mockParams);

            assertNotNull(result);
            AttributeBean attributeBean = result.getSamlAttributes().get(0);
            assertEquals(attributeBean.getSimpleName(), CLAIM_URI_FRAGMENT);
            assertEquals(attributeBean.getQualifiedName(), CLAIM_NAMESPACE);
        }
    }

    @Test
    public void testGetStatement_saml2TokenType_setsNameFormat() throws Exception {

        try (MockedStatic<IdentityClaimManager> mockedClaimManager = mockStatic(IdentityClaimManager.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ClaimsUtils> mockedClaimsUtils = mockStatic(ClaimsUtils.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            setupClaimManager(mockedClaimManager, mockedTenantUtil, new Claim[0]);
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn("false");

            ProcessedClaimCollection claims = buildSingleClaimCollection(CLAIM_URI);
            TokenProviderParameters mockParams = buildMockParams(
                    WSS4JConstants.WSS_SAML2_TOKEN_TYPE, claims, mockedClaimsUtils);

            AttributeStatementBean result = new TestableCustomAttributeProvider().getStatement(mockParams);

            assertEquals(result.getSamlAttributes().get(0).getNameFormat(), CLAIM_URI);
        }
    }

    @Test
    public void testGetStatement_saml11TokenType_doesNotSetNameFormat() throws Exception {

        try (MockedStatic<IdentityClaimManager> mockedClaimManager = mockStatic(IdentityClaimManager.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ClaimsUtils> mockedClaimsUtils = mockStatic(ClaimsUtils.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            setupClaimManager(mockedClaimManager, mockedTenantUtil, new Claim[0]);
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn("false");

            ProcessedClaimCollection claims = buildSingleClaimCollection(CLAIM_URI);
            TokenProviderParameters mockParams = buildMockParams(
                    WSS4JConstants.WSS_SAML_TOKEN_TYPE, claims, mockedClaimsUtils);

            AttributeStatementBean result = new TestableCustomAttributeProvider().getStatement(mockParams);

            // nameFormat is not set for SAML 1.1
            assertTrue(result.getSamlAttributes().get(0).getNameFormat() == null
                    || result.getSamlAttributes().get(0).getNameFormat().isEmpty());
        }
    }

    @Test
    public void testGetStatement_claimUriTrailingSlash_noFragmentExtraction() throws Exception {

        try (MockedStatic<IdentityClaimManager> mockedClaimManager = mockStatic(IdentityClaimManager.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ClaimsUtils> mockedClaimsUtils = mockStatic(ClaimsUtils.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            setupClaimManager(mockedClaimManager, mockedTenantUtil, new Claim[0]);
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn("false");

            // Claim URI ending with "/" — no fragment to extract, both simpleName and qualifiedName stay as-is
            String trailingSlashUri = "http://wso2.org/claims/";
            ProcessedClaimCollection claims = buildSingleClaimCollection(trailingSlashUri);
            TokenProviderParameters mockParams = buildMockParams(
                    WSS4JConstants.WSS_SAML_TOKEN_TYPE, claims, mockedClaimsUtils);

            AttributeStatementBean result = new TestableCustomAttributeProvider().getStatement(mockParams);

            AttributeBean attributeBean = result.getSamlAttributes().get(0);
            assertEquals(attributeBean.getSimpleName(), trailingSlashUri);
            assertEquals(attributeBean.getQualifiedName(), trailingSlashUri);
        }
    }

    @Test
    public void testGetStatement_multipleClaimsProcessed() throws Exception {

        try (MockedStatic<IdentityClaimManager> mockedClaimManager = mockStatic(IdentityClaimManager.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ClaimsUtils> mockedClaimsUtils = mockStatic(ClaimsUtils.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            Claim emailClaim = new Claim();
            emailClaim.setClaimUri(CLAIM_URI);
            emailClaim.setDisplayTag(CLAIM_DISPLAY_TAG);
            Claim firstnameClaim = new Claim();
            firstnameClaim.setClaimUri("http://wso2.org/claims/givenname");
            firstnameClaim.setDisplayTag("First Name");
            setupClaimManager(mockedClaimManager, mockedTenantUtil,
                    new Claim[]{emailClaim, firstnameClaim});

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.STS.PASSIVE_STS_ENABLE_CLAIM_DESCRIPTION_IN_ATTRIBUTE_NAME))
                    .thenReturn("true");

            ProcessedClaim pc1 = new ProcessedClaim();
            pc1.setClaimType(CLAIM_URI);
            pc1.setValues(Collections.singletonList("test@example.com"));
            ProcessedClaim pc2 = new ProcessedClaim();
            pc2.setClaimType("http://wso2.org/claims/givenname");
            pc2.setValues(Collections.singletonList("John"));
            ProcessedClaimCollection claimCollection = new ProcessedClaimCollection();
            claimCollection.add(pc1);
            claimCollection.add(pc2);

            TokenProviderParameters mockParams = buildMockParams(
                    WSS4JConstants.WSS_SAML2_TOKEN_TYPE, claimCollection, mockedClaimsUtils);

            AttributeStatementBean result = new TestableCustomAttributeProvider().getStatement(mockParams);

            assertEquals(result.getSamlAttributes().size(), 2);
            assertEquals(result.getSamlAttributes().get(0).getSimpleName(), CLAIM_DISPLAY_TAG);
            assertEquals(result.getSamlAttributes().get(1).getSimpleName(), "First Name");
        }
    }

    @Test
    public void testGetStatement_identityExceptionOnClaimLoad_fallsBackToUriFragment() throws Exception {

        try (MockedStatic<IdentityClaimManager> mockedClaimManager = mockStatic(IdentityClaimManager.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ClaimsUtils> mockedClaimsUtils = mockStatic(ClaimsUtils.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            // IdentityClaimManager.getInstance() throws IdentityException — supportedClaims stays empty
            mockedClaimManager.when(IdentityClaimManager::getInstance)
                    .thenThrow(new IdentityException("Failed to get claim manager"));
            mockedTenantUtil.when(() -> IdentityTenantUtil.getRealm(anyString(), any()))
                    .thenReturn(mock(UserRealm.class));

            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.STS.PASSIVE_STS_ENABLE_CLAIM_DESCRIPTION_IN_ATTRIBUTE_NAME))
                    .thenReturn("true");

            ProcessedClaimCollection claims = buildSingleClaimCollection(CLAIM_URI);
            TokenProviderParameters mockParams = buildMockParams(
                    WSS4JConstants.WSS_SAML2_TOKEN_TYPE, claims, mockedClaimsUtils);

            // getStatement must not throw; with empty supportedClaims it falls back to URI fragment
            AttributeStatementBean result = new TestableCustomAttributeProvider().getStatement(mockParams);

            assertNotNull(result);
            AttributeBean attributeBean = result.getSamlAttributes().get(0);
            assertEquals(attributeBean.getSimpleName(), CLAIM_URI_FRAGMENT);
            assertEquals(attributeBean.getQualifiedName(), CLAIM_NAMESPACE);
        }
    }
}
