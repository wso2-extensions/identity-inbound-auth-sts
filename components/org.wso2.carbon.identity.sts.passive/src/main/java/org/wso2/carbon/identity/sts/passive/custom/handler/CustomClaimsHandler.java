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
package org.wso2.carbon.identity.sts.passive.custom.handler;

import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.rt.security.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * A custom ClaimsHandler implementation to be used in the implementation.
 */
public class CustomClaimsHandler implements ClaimsHandler {

    private static List<String> knownURIs = new ArrayList<>();
    private HashMap<String, String> requestedClaims = new HashMap<>();

    /**
     * Create a processed claim collection using the claim values and params provided.
     *
     * @param claims     The unprocessed claims.
     * @param parameters The claim parameters.
     * @return The processed claims.
     */
    public ProcessedClaimCollection retrieveClaimValues(
            ClaimCollection claims, ClaimsParameters parameters) {

        if (claims != null && !claims.isEmpty()) {
            ProcessedClaimCollection claimCollection = new ProcessedClaimCollection();
            for (Claim requestClaim : claims) {
                ProcessedClaim claim = new ProcessedClaim();
                claim.setClaimType(requestClaim.getClaimType());
                if (knownURIs.contains(requestClaim.getClaimType()) &&
                        requestedClaims.containsKey(requestClaim.getClaimType())) {
                    claim.addValue(requestedClaims.get(requestClaim.getClaimType()));
                }
                claimCollection.add(claim);
            }
            return claimCollection;
        }

        return null;
    }

    /**
     * Get the list of supported claim URIs.
     *
     * @return List of supported claim URIs.
     */
    public List<String> getSupportedClaimTypes() {

        return knownURIs;
    }

    /**
     * Set the list of supported claim URIs.
     *
     * @param knownURIs New list to be set as the known URIs.
     */
    public static void setKnownURIs(List<String> knownURIs) {

        CustomClaimsHandler.knownURIs = knownURIs;
    }

    /**
     * Get claim URIs and values in the form of a HashMap.
     *
     * @return HashMap containing the claim URIs and values.
     */
    public HashMap<String, String> getRequestedClaims() {

        return requestedClaims;
    }

    /**
     * Set claim key value pair(the URI and value).
     *
     * @param requestedClaims The new HashMap of claims key value pair.
     */
    public void setRequestedClaims(HashMap<String, String> requestedClaims) {

        this.requestedClaims = requestedClaims;
    }
}
