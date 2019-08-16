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
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.om.util.Base64;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.mex2.util.KeyUtil;
import java.security.cert.X509Certificate;


public class MexGetService {

        private static final Log log = LogFactory.getLog(MexGetService.class);
        private static final String SERVICE_URL = "/services";
        private static final String STS_END_POINT = "/wso2carbon-sts.wso2carbon-stsHttpsSoap12Endpoint";
        private static final String KERBEROS_MIXED = "/kerberosmixed";
        private static final String MEX_URI_O = "/mexut/mex/get1";
        private static final String MEX_URI_1 = "/mexut/mex/get2";
        private static final String MEX_URI_2 = "/mexut/mex/get3";


        public OMElement get(OMElement element) throws
                Exception {

                if (log.isDebugEnabled()) {
                        log.debug("---------------begin POST Mex get--------------------");
                }

                MessageContext msgCtx = MessageContext.getCurrentMessageContext();
                String service = msgCtx.getAxisService().getName();

                if (StringUtils.isEmpty(service)) {
                        throw new AxisFault("Service Mex has not registered successfully");

                }

                String CarbonserviceURL = IdentityUtil.getServerURL("", true, true);

                X509Certificate cert;
                cert = KeyUtil.getCertificateToIncludeInMex(service);

                if (cert == null) {
                        throw new AxisFault("STS's certificate is null");
                }

                byte[] byteArray = cert.getEncoded();
                String encodedCertificate = Base64.encode(byteArray);

                if (StringUtils.isEmpty(encodedCertificate)) {
                        throw new AxisFault("STS's certificate has not successfully encoded");
                }

                if (log.isDebugEnabled()) {
                        log.debug("Encoded Certificate value: " + encodedCertificate);
                }

                String stsEndpointUrl = CarbonserviceURL + MexGetService.SERVICE_URL + MexGetService.STS_END_POINT;
                String kerbosEndpointUrl = CarbonserviceURL + MexGetService.SERVICE_URL + MexGetService.KERBEROS_MIXED;

                if (StringUtils.isBlank(stsEndpointUrl) || StringUtils.isBlank(kerbosEndpointUrl)) {
                        throw new AxisFault("STS");
                }

                if (log.isDebugEnabled()) {
                        log.debug("stsEndpointUrl:=> " + stsEndpointUrl + "mexEndpointUrl:=> " + kerbosEndpointUrl);

                }

                String response = "<Metadata xmlns=\"http://schemas.xmlsoap.org/ws/2004/09/mex\" xmlns:wsx=\"http://schemas.xmlsoap.org/ws/2004/09/mex\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n" +
                        "   <wsx:MetadataSection xmlns=\"\" Dialect=\"http://schemas.xmlsoap.org/wsdl/\" Identifier=\"http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice\">\n" +
                        "      <wsdl:definitions xmlns:wsdl=\"http://schemas.xmlsoap.org/wsdl/\" xmlns:msc=\"http://schemas.microsoft.com/ws/2005/12/wsdl/contract\" xmlns:soap=\"http://schemas.xmlsoap.org/wsdl/soap/\" xmlns:soap12=\"http://schemas.xmlsoap.org/wsdl/soap12/\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:tns=\"http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice\" xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsa10=\"http://www.w3.org/2005/08/addressing\" xmlns:wsam=\"http://www.w3.org/2007/05/addressing/metadata\" xmlns:wsap=\"http://schemas.xmlsoap.org/ws/2004/08/addressing/policy\" xmlns:wsaw=\"http://www.w3.org/2006/05/addressing/wsdl\" xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" name=\"SecurityTokenService\" targetNamespace=\"http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice\">\n" +
                        "         <wsp:Policy wsu:Id=\"CustomBinding_IWSTrustFeb2005Async_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <http:NegotiateAuthentication xmlns:http=\"http://schemas.microsoft.com/ws/06/2004/policy/http\" />\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"CertificateWSTrustBinding_IWSTrustFeb2005Async_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:X509Token sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:RequireThumbprintReference />\n" +
                        "                              <sp:WssX509V3Token10 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:X509Token>\n" +
                        "                        <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportRefThumbprint />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust10>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"CertificateWSTrustBinding_IWSTrustFeb2005Async1_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken RequireClientCertificate=\"true\" />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrustFeb2005Async_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:SymmetricBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:ProtectionToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:X509Token sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\">\n" +
                        "                                 <wsp:Policy>\n" +
                        "                                    <sp:RequireDerivedKeys />\n" +
                        "                                    <sp:RequireThumbprintReference />\n" +
                        "                                    <sp:WssX509V3Token10 />\n" +
                        "                                 </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:ProtectionToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                        <sp:EncryptSignature />\n" +
                        "                        <sp:OnlySignEntireHeadersAndBody />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:SymmetricBinding>\n" +
                        "                  <sp:SignedSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:WssUsernameToken10 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:SignedSupportingTokens>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportRefThumbprint />\n" +
                        "                        <sp:MustSupportRefEncryptedKey />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust10>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrustFeb2005Async_TrustFeb2005IssueAsync_Input_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:SignedParts xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <sp:Body />\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"From\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"FaultTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"ReplyTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"MessageID\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"RelatesTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"Action\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "                  <sp:EncryptedParts xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <sp:Body />\n" +
                        "                  </sp:EncryptedParts>\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrustFeb2005Async_TrustFeb2005IssueAsync_output_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:SignedParts xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <sp:Body />\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"From\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"FaultTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"ReplyTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"MessageID\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"RelatesTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                     <sp:Header Name=\"Action\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "                  <sp:EncryptedParts xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <sp:Body />\n" +
                        "                  </sp:EncryptedParts>\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrustFeb2005Async1_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:SignedSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:WssUsernameToken10 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:SignedSupportingTokens>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy />\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust10>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"CustomBinding_IWSTrustFeb2005Async1_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic128 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:KerberosToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Once\">\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:WssGssKerberosV5ApReqToken11 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:KerberosToken>\n" +
                        "                        <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy />\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust10>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"IssuedTokenWSTrustBinding_IWSTrustFeb2005Async_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:IssuedToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <sp:RequestSecurityTokenTemplate>\n" +
                        "                              <t:KeyType>http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey</t:KeyType>\n" +
                        "                              <t:EncryptWith>http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p</t:EncryptWith>\n" +
                        "                              <t:SignatureAlgorithm>http://www.w3.org/2000/09/xmldsig#rsa-sha1</t:SignatureAlgorithm>\n" +
                        "                              <t:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</t:CanonicalizationAlgorithm>\n" +
                        "                              <t:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</t:EncryptionAlgorithm>\n" +
                        "                           </sp:RequestSecurityTokenTemplate>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:RequireInternalReference />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:IssuedToken>\n" +
                        "                        <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy />\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust10>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:IssuedToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <sp:RequestSecurityTokenTemplate>\n" +
                        "                              <t:KeyType>http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey</t:KeyType>\n" +
                        "                              <t:KeySize>256</t:KeySize>\n" +
                        "                              <t:EncryptWith>http://www.w3.org/2001/04/xmlenc#aes256-cbc</t:EncryptWith>\n" +
                        "                              <t:SignatureAlgorithm>http://www.w3.org/2000/09/xmldsig#hmac-sha1</t:SignatureAlgorithm>\n" +
                        "                              <t:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</t:CanonicalizationAlgorithm>\n" +
                        "                              <t:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</t:EncryptionAlgorithm>\n" +
                        "                           </sp:RequestSecurityTokenTemplate>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:RequireInternalReference />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:IssuedToken>\n" +
                        "                        <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy />\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust10>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"CustomBinding_IWSTrust13Async_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic128 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:KerberosToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Once\">\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:WssGssKerberosV5ApReqToken11 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:KerberosToken>\n" +
                        "                        <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy />\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust13>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"CertificateWSTrustBinding_IWSTrust13Async_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:X509Token sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:RequireThumbprintReference />\n" +
                        "                              <sp:WssX509V3Token10 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:X509Token>\n" +
                        "                        <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportRefThumbprint />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust13>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrust13Async_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:SignedEncryptedSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:WssUsernameToken10 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:SignedEncryptedSupportingTokens>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy />\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust13>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"IssuedTokenWSTrustBinding_IWSTrust13Async_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:IssuedToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <sp:RequestSecurityTokenTemplate>\n" +
                        "                              <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey</trust:KeyType>\n" +
                        "                              <trust:KeyWrapAlgorithm>http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p</trust:KeyWrapAlgorithm>\n" +
                        "                              <trust:EncryptWith>http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p</trust:EncryptWith>\n" +
                        "                              <trust:SignatureAlgorithm>http://www.w3.org/2000/09/xmldsig#rsa-sha1</trust:SignatureAlgorithm>\n" +
                        "                              <trust:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</trust:CanonicalizationAlgorithm>\n" +
                        "                              <trust:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</trust:EncryptionAlgorithm>\n" +
                        "                           </sp:RequestSecurityTokenTemplate>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:RequireInternalReference />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:IssuedToken>\n" +
                        "                        <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy />\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust13>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsp:Policy wsu:Id=\"IssuedTokenWSTrustBinding_IWSTrust13Async1_policy\">\n" +
                        "            <wsp:ExactlyOne>\n" +
                        "               <wsp:All>\n" +
                        "                  <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:HttpsToken />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Basic256 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:Strict />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportBinding>\n" +
                        "                  <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:IssuedToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                           <sp:RequestSecurityTokenTemplate>\n" +
                        "                              <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</trust:KeyType>\n" +
                        "                              <trust:KeySize>256</trust:KeySize>\n" +
                        "                              <trust:KeyWrapAlgorithm>http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p</trust:KeyWrapAlgorithm>\n" +
                        "                              <trust:EncryptWith>http://www.w3.org/2001/04/xmlenc#aes256-cbc</trust:EncryptWith>\n" +
                        "                              <trust:SignatureAlgorithm>http://www.w3.org/2000/09/xmldsig#hmac-sha1</trust:SignatureAlgorithm>\n" +
                        "                              <trust:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</trust:CanonicalizationAlgorithm>\n" +
                        "                              <trust:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</trust:EncryptionAlgorithm>\n" +
                        "                           </sp:RequestSecurityTokenTemplate>\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:RequireInternalReference />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:IssuedToken>\n" +
                        "                        <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                        <sp:SignedParts>\n" +
                        "                           <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                        </sp:SignedParts>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:EndorsingSupportingTokens>\n" +
                        "                  <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy />\n" +
                        "                  </sp:Wss11>\n" +
                        "                  <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:MustSupportIssuedTokens />\n" +
                        "                        <sp:RequireClientEntropy />\n" +
                        "                        <sp:RequireServerEntropy />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Trust13>\n" +
                        "                  <wsaw:UsingAddressing />\n" +
                        "               </wsp:All>\n" +
                        "            </wsp:ExactlyOne>\n" +
                        "         </wsp:Policy>\n" +
                        "         <wsdl:types>\n" +
                        "            <xsd:schema targetNamespace=\"http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice/Imports\">\n" +
                        "               <xsd:import namespace=\"http://schemas.microsoft.com/Message\" />\n" +
                        "               <xsd:import namespace=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" />\n" +
                        "               <xsd:import namespace=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" />\n" +
                        "            </xsd:schema>\n" +
                        "         </wsdl:types>\n" +
                        "         <wsdl:message name=\"IWSTrustFeb2005Async_TrustFeb2005IssueAsync_InputMessage\">\n" +
                        "            <wsdl:part name=\"request\" element=\"t:RequestSecurityToken\" />\n" +
                        "         </wsdl:message>\n" +
                        "         <wsdl:message name=\"IWSTrustFeb2005Async_TrustFeb2005IssueAsync_OutputMessage\">\n" +
                        "            <wsdl:part name=\"TrustFeb2005IssueAsyncResult\" element=\"t:RequestSecurityTokenResponse\" />\n" +
                        "         </wsdl:message>\n" +
                        "         <wsdl:message name=\"IWSTrust13Async_Trust13IssueAsync_InputMessage\">\n" +
                        "            <wsdl:part name=\"request\" element=\"trust:RequestSecurityToken\" />\n" +
                        "         </wsdl:message>\n" +
                        "         <wsdl:message name=\"IWSTrust13Async_Trust13IssueAsync_OutputMessage\">\n" +
                        "            <wsdl:part name=\"Trust13IssueAsyncResult\" element=\"trust:RequestSecurityTokenResponseCollection\" />\n" +
                        "         </wsdl:message>\n" +
                        "         <wsdl:portType name=\"IWSTrustFeb2005Async\">\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <wsdl:input wsaw:Action=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" message=\"tns:IWSTrustFeb2005Async_TrustFeb2005IssueAsync_InputMessage\" />\n" +
                        "               <wsdl:output wsaw:Action=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue\" message=\"tns:IWSTrustFeb2005Async_TrustFeb2005IssueAsync_OutputMessage\" />\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:portType>\n" +
                        "         <wsdl:portType name=\"IWSTrust13Async\">\n" +
                        "            <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "               <wsdl:input wsaw:Action=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" message=\"tns:IWSTrust13Async_Trust13IssueAsync_InputMessage\" />\n" +
                        "               <wsdl:output wsaw:Action=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal\" message=\"tns:IWSTrust13Async_Trust13IssueAsync_OutputMessage\" />\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:portType>\n" +
                        "         <wsdl:binding name=\"CustomBinding_IWSTrustFeb2005Async\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#CustomBinding_IWSTrustFeb2005Async_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"CertificateWSTrustBinding_IWSTrustFeb2005Async\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#CertificateWSTrustBinding_IWSTrustFeb2005Async_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"CertificateWSTrustBinding_IWSTrustFeb2005Async1\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#CertificateWSTrustBinding_IWSTrustFeb2005Async1_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"UserNameWSTrustBinding_IWSTrustFeb2005Async\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrustFeb2005Async_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrustFeb2005Async_TrustFeb2005IssueAsync_Input_policy\" />\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrustFeb2005Async_TrustFeb2005IssueAsync_output_policy\" />\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"UserNameWSTrustBinding_IWSTrustFeb2005Async1\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrustFeb2005Async1_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"CustomBinding_IWSTrustFeb2005Async1\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#CustomBinding_IWSTrustFeb2005Async1_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"IssuedTokenWSTrustBinding_IWSTrustFeb2005Async\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#IssuedTokenWSTrustBinding_IWSTrustFeb2005Async_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"CustomBinding_IWSTrust13Async\" type=\"tns:IWSTrust13Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#CustomBinding_IWSTrust13Async_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"CertificateWSTrustBinding_IWSTrust13Async\" type=\"tns:IWSTrust13Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#CertificateWSTrustBinding_IWSTrust13Async_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"UserNameWSTrustBinding_IWSTrust13Async\" type=\"tns:IWSTrust13Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrust13Async_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"IssuedTokenWSTrustBinding_IWSTrust13Async\" type=\"tns:IWSTrust13Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#IssuedTokenWSTrustBinding_IWSTrust13Async_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:binding name=\"IssuedTokenWSTrustBinding_IWSTrust13Async1\" type=\"tns:IWSTrust13Async\">\n" +
                        "            <wsp:PolicyReference URI=\"#IssuedTokenWSTrustBinding_IWSTrust13Async1_policy\" />\n" +
                        "            <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "            <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "               <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "               <wsdl:input>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:input>\n" +
                        "               <wsdl:output>\n" +
                        "                  <soap12:body use=\"literal\" />\n" +
                        "               </wsdl:output>\n" +
                        "            </wsdl:operation>\n" +
                        "         </wsdl:binding>\n" +
                        "         <wsdl:service name=\"SecurityTokenService\">\n" +
                        "            <wsdl:port name=\"UserNameWSTrustBinding_IWSTrustFeb2005Async\" binding=\"tns:UserNameWSTrustBinding_IWSTrustFeb2005Async\">\n" +
                        "               <soap12:address location=\"$params1\" />\n" +
                        "               <wsa10:EndpointReference>\n" +
                        "                  <wsa10:Address>$params1</wsa10:Address>\n" +
                        "                  <Identity xmlns=\"http://schemas.xmlsoap.org/ws/2006/02/addressingidentity\">\n" +
                        "                     <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                        "                        <X509Data>\n" +
                        "                           <X509Certificate>$params3</X509Certificate>\n" +
                        "                        </X509Data>\n" +
                        "                     </KeyInfo>\n" +
                        "                  </Identity>\n" +
                        "               </wsa10:EndpointReference>\n" +
                        "            </wsdl:port>\n" +
                        "            <wsdl:port name=\"UserNameWSTrustBinding_IWSTrustFeb2005Async1\" binding=\"tns:UserNameWSTrustBinding_IWSTrustFeb2005Async1\">\n" +
                        "               <soap12:address location=\"$params1\" />\n" +
                        "               <wsa10:EndpointReference>\n" +
                        "                  <wsa10:Address>$params1</wsa10:Address>\n" +
                        "               </wsa10:EndpointReference>\n" +
                        "            </wsdl:port>\n" +
                        "            <wsdl:port name=\"CustomBinding_IWSTrustFeb2005Async1\" binding=\"tns:CustomBinding_IWSTrustFeb2005Async1\">\n" +
                        "               <soap12:address location=\"$params2\" />\n" +
                        "               <wsa10:EndpointReference>\n" +
                        "                  <wsa10:Address>$params2</wsa10:Address>\n" +
                        "               </wsa10:EndpointReference>\n" +
                        "            </wsdl:port>\n" +
                        "            <wsdl:port name=\"CustomBinding_IWSTrust13Async\" binding=\"tns:CustomBinding_IWSTrust13Async\">\n" +
                        "               <soap12:address location=\"$params2\" />\n" +
                        "               <wsa10:EndpointReference>\n" +
                        "                  <wsa10:Address>$params2</wsa10:Address>\n" +
                        "               </wsa10:EndpointReference>\n" +
                        "            </wsdl:port>\n" +
                        "            <wsdl:port name=\"UserNameWSTrustBinding_IWSTrust13Async\" binding=\"tns:UserNameWSTrustBinding_IWSTrust13Async\">\n" +
                        "               <soap12:address location=\"$params1\" />\n" +
                        "               <wsa10:EndpointReference>\n" +
                        "                  <wsa10:Address>$params1</wsa10:Address>\n" +
                        "               </wsa10:EndpointReference>\n" +
                        "            </wsdl:port>\n" +
                        "         </wsdl:service>\n" +
                        "      </wsdl:definitions>\n" +
                        "   </wsx:MetadataSection>\n" +
                        "   <wsx:MetadataSection xmlns=\"\" Dialect=\"http://www.w3.org/2001/XMLSchema\" Identifier=\"http://schemas.microsoft.com/Message\">\n" +
                        "      <xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:tns=\"http://schemas.microsoft.com/Message\" elementFormDefault=\"qualified\" targetNamespace=\"http://schemas.microsoft.com/Message\">\n" +
                        "         <xs:complexType name=\"MessageBody\">\n" +
                        "            <xs:sequence>\n" +
                        "               <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" />\n" +
                        "            </xs:sequence>\n" +
                        "         </xs:complexType>\n" +
                        "      </xs:schema>\n" +
                        "   </wsx:MetadataSection>\n" +
                        "   <wsx:MetadataSection xmlns=\"\" Dialect=\"http://www.w3.org/2001/XMLSchema\" Identifier=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">\n" +
                        "      <xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" elementFormDefault=\"qualified\" targetNamespace=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">\n" +
                        "         <xs:element name=\"RequestSecurityToken\" type=\"wst:RequestSecurityTokenType\" />\n" +
                        "         <xs:complexType name=\"RequestSecurityTokenType\">\n" +
                        "            <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\n" +
                        "               <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" processContents=\"lax\" />\n" +
                        "            </xs:choice>\n" +
                        "            <xs:attribute name=\"Context\" type=\"xs:anyURI\" use=\"optional\" />\n" +
                        "            <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                        "         </xs:complexType>\n" +
                        "         <xs:element name=\"RequestSecurityTokenResponse\" type=\"wst:RequestSecurityTokenResponseType\" />\n" +
                        "         <xs:complexType name=\"RequestSecurityTokenResponseType\">\n" +
                        "            <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\n" +
                        "               <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" processContents=\"lax\" />\n" +
                        "            </xs:choice>\n" +
                        "            <xs:attribute name=\"Context\" type=\"xs:anyURI\" use=\"optional\" />\n" +
                        "            <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                        "         </xs:complexType>\n" +
                        "      </xs:schema>\n" +
                        "   </wsx:MetadataSection>\n" +
                        "   <wsx:MetadataSection xmlns=\"\" Dialect=\"http://www.w3.org/2001/XMLSchema\" Identifier=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">\n" +
                        "      <xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" elementFormDefault=\"qualified\" targetNamespace=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">\n" +
                        "         <xs:element name=\"RequestSecurityToken\" type=\"trust:RequestSecurityTokenType\" />\n" +
                        "         <xs:complexType name=\"RequestSecurityTokenType\">\n" +
                        "            <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\n" +
                        "               <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" processContents=\"lax\" />\n" +
                        "            </xs:choice>\n" +
                        "            <xs:attribute name=\"Context\" type=\"xs:anyURI\" use=\"optional\" />\n" +
                        "            <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                        "         </xs:complexType>\n" +
                        "         <xs:element name=\"RequestSecurityTokenResponse\" type=\"trust:RequestSecurityTokenResponseType\" />\n" +
                        "         <xs:complexType name=\"RequestSecurityTokenResponseType\">\n" +
                        "            <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\n" +
                        "               <xs:any minOccurs=\"0\" maxOccurs=\"unbounded\" namespace=\"##any\" processContents=\"lax\" />\n" +
                        "            </xs:choice>\n" +
                        "            <xs:attribute name=\"Context\" type=\"xs:anyURI\" use=\"optional\" />\n" +
                        "            <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                        "         </xs:complexType>\n" +
                        "         <xs:element name=\"RequestSecurityTokenResponseCollection\" type=\"trust:RequestSecurityTokenResponseCollectionType\" />\n" +
                        "         <xs:complexType name=\"RequestSecurityTokenResponseCollectionType\">\n" +
                        "            <xs:sequence>\n" +
                        "               <xs:element minOccurs=\"1\" maxOccurs=\"unbounded\" ref=\"trust:RequestSecurityTokenResponse\" />\n" +
                        "            </xs:sequence>\n" +
                        "            <xs:anyAttribute namespace=\"##other\" processContents=\"lax\" />\n" +
                        "         </xs:complexType>\n" +
                        "      </xs:schema>\n" +
                        "   </wsx:MetadataSection>\n" +
                        "</Metadata>";

                response = response.replace("$params1", stsEndpointUrl);
                response = response.replace("$params2", kerbosEndpointUrl);
                response = response.replace("$params3", encodedCertificate);

                OMElement omBody = AXIOMUtil.stringToOM(response);
                if (log.isDebugEnabled()) {
                        log.debug("Mex-Response => " + response);

                }

                return omBody;

        }


        public OMElement get2(OMElement element) throws
                Exception {


                if (log.isDebugEnabled()) {
                        log.debug("---------------begin REST Mex get--------------------");
                }

                MessageContext msgCtx = MessageContext.getCurrentMessageContext();
                String service = msgCtx.getAxisService().getName();

                if (StringUtils.isEmpty(service)) {
                        throw new AxisFault("Service Mex has not registered successfully");

                }

                String CarbonserviceURL = IdentityUtil.getServerURL("", true, true);

                X509Certificate cert;
                cert = KeyUtil.getCertificateToIncludeInMex(service);

                if (cert == null) {
                        throw new AxisFault("STS's certificate is null");
                }

                byte[] byteArray = cert.getEncoded();
                String encodedCertificate = Base64.encode(byteArray);

                if (StringUtils.isEmpty(encodedCertificate)) {
                        throw new AxisFault("STS's certificate has not successfully encoded");
                }

                if (log.isDebugEnabled()) {
                        log.debug("Encoded Certificate value: " + encodedCertificate);
                }

                String stsEndpointUrl = CarbonserviceURL + MexGetService.SERVICE_URL + MexGetService.STS_END_POINT;
                String kerbosEndpointUrl = CarbonserviceURL + MexGetService.SERVICE_URL + MexGetService.KERBEROS_MIXED;
                String mexXSD0 = CarbonserviceURL + MexGetService.MEX_URI_O;
                String mexXSD1 = CarbonserviceURL + MexGetService.MEX_URI_1;
                String mexXSD2 = CarbonserviceURL + MexGetService.MEX_URI_2;

                if (StringUtils.isBlank(mexXSD0) || StringUtils.isBlank(mexXSD1) || StringUtils.isBlank(mexXSD2)) {
                        throw new AxisFault("STS");
                }

                if (StringUtils.isBlank(stsEndpointUrl) || StringUtils.isBlank(kerbosEndpointUrl)) {
                        throw new AxisFault("STS");
                }


                if (log.isDebugEnabled()) {
                        log.debug("stsEndpointUrl:=> " + stsEndpointUrl + "mexEndpointUrl:=> " + kerbosEndpointUrl);

                }

                String response = "<wsdl:definitions xmlns:wsdl=\"http://schemas.xmlsoap.org/wsdl/\" xmlns:msc=\"http://schemas.microsoft.com/ws/2005/12/wsdl/contract\" xmlns:soap=\"http://schemas.xmlsoap.org/wsdl/soap/\" xmlns:soap12=\"http://schemas.xmlsoap.org/wsdl/soap12/\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xmlns:tns=\"http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice\" xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsa10=\"http://www.w3.org/2005/08/addressing\" xmlns:wsam=\"http://www.w3.org/2007/05/addressing/metadata\" xmlns:wsap=\"http://schemas.xmlsoap.org/ws/2004/08/addressing/policy\" xmlns:wsaw=\"http://www.w3.org/2006/05/addressing/wsdl\" xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wsx=\"http://schemas.xmlsoap.org/ws/2004/09/mex\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" name=\"SecurityTokenService\" targetNamespace=\"http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice\">\n" +
                        "   <wsp:Policy wsu:Id=\"CustomBinding_IWSTrustFeb2005Async_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <http:NegotiateAuthentication xmlns:http=\"http://schemas.microsoft.com/ws/06/2004/policy/http\" />\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"CertificateWSTrustBinding_IWSTrustFeb2005Async_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:X509Token sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:RequireThumbprintReference />\n" +
                        "                        <sp:WssX509V3Token10 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:X509Token>\n" +
                        "                  <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportRefThumbprint />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust10>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"CertificateWSTrustBinding_IWSTrustFeb2005Async1_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken RequireClientCertificate=\"true\" />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrustFeb2005Async_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:SymmetricBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:ProtectionToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:X509Token sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\">\n" +
                        "                           <wsp:Policy>\n" +
                        "                              <sp:RequireDerivedKeys />\n" +
                        "                              <sp:RequireThumbprintReference />\n" +
                        "                              <sp:WssX509V3Token10 />\n" +
                        "                           </wsp:Policy>\n" +
                        "                        </sp:X509Token>\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:ProtectionToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "                  <sp:EncryptSignature />\n" +
                        "                  <sp:OnlySignEntireHeadersAndBody />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:SymmetricBinding>\n" +
                        "            <sp:SignedSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:UsernameToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:WssUsernameToken10 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:UsernameToken>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:SignedSupportingTokens>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportRefThumbprint />\n" +
                        "                  <sp:MustSupportRefEncryptedKey />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust10>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrustFeb2005Async_TrustFeb2005IssueAsync_Input_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:SignedParts xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <sp:Body />\n" +
                        "               <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"From\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"FaultTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"ReplyTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"MessageID\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"RelatesTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"Action\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "            </sp:SignedParts>\n" +
                        "            <sp:EncryptedParts xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <sp:Body />\n" +
                        "            </sp:EncryptedParts>\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrustFeb2005Async_TrustFeb2005IssueAsync_output_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:SignedParts xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <sp:Body />\n" +
                        "               <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"From\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"FaultTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"ReplyTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"MessageID\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"RelatesTo\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "               <sp:Header Name=\"Action\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "            </sp:SignedParts>\n" +
                        "            <sp:EncryptedParts xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <sp:Body />\n" +
                        "            </sp:EncryptedParts>\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrustFeb2005Async1_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:SignedSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:UsernameToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:WssUsernameToken10 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:UsernameToken>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:SignedSupportingTokens>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy />\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust10>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"CustomBinding_IWSTrustFeb2005Async1_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic128 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:KerberosToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Once\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:WssGssKerberosV5ApReqToken11 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:KerberosToken>\n" +
                        "                  <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy />\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust10>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"IssuedTokenWSTrustBinding_IWSTrustFeb2005Async_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:IssuedToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <sp:RequestSecurityTokenTemplate>\n" +
                        "                        <t:KeyType>http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey</t:KeyType>\n" +
                        "                        <t:EncryptWith>http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p</t:EncryptWith>\n" +
                        "                        <t:SignatureAlgorithm>http://www.w3.org/2000/09/xmldsig#rsa-sha1</t:SignatureAlgorithm>\n" +
                        "                        <t:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</t:CanonicalizationAlgorithm>\n" +
                        "                        <t:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</t:EncryptionAlgorithm>\n" +
                        "                     </sp:RequestSecurityTokenTemplate>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:RequireInternalReference />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:IssuedToken>\n" +
                        "                  <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy />\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust10>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken RequireClientCertificate=\"false\" />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:IssuedToken sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <sp:RequestSecurityTokenTemplate>\n" +
                        "                        <t:KeyType>http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey</t:KeyType>\n" +
                        "                        <t:KeySize>256</t:KeySize>\n" +
                        "                        <t:EncryptWith>http://www.w3.org/2001/04/xmlenc#aes256-cbc</t:EncryptWith>\n" +
                        "                        <t:SignatureAlgorithm>http://www.w3.org/2000/09/xmldsig#hmac-sha1</t:SignatureAlgorithm>\n" +
                        "                        <t:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</t:CanonicalizationAlgorithm>\n" +
                        "                        <t:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</t:EncryptionAlgorithm>\n" +
                        "                     </sp:RequestSecurityTokenTemplate>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:RequireInternalReference />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:IssuedToken>\n" +
                        "                  <mssp:RsaToken xmlns:mssp=\"http://schemas.microsoft.com/ws/2005/07/securitypolicy\" sp:IncludeToken=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy />\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust10 xmlns:sp=\"http://schemas.xmlsoap.org/ws/2005/07/securitypolicy\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust10>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"CustomBinding_IWSTrust13Async_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic128 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:KerberosToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Once\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:WssGssKerberosV5ApReqToken11 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:KerberosToken>\n" +
                        "                  <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy />\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust13>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"CertificateWSTrustBinding_IWSTrust13Async_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:X509Token sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:RequireThumbprintReference />\n" +
                        "                        <sp:WssX509V3Token10 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:X509Token>\n" +
                        "                  <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportRefThumbprint />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust13>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"UserNameWSTrustBinding_IWSTrust13Async_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:SignedEncryptedSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:WssUsernameToken10 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:UsernameToken>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:SignedEncryptedSupportingTokens>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy />\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust13>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"IssuedTokenWSTrustBinding_IWSTrust13Async_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:IssuedToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <sp:RequestSecurityTokenTemplate>\n" +
                        "                        <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey</trust:KeyType>\n" +
                        "                        <trust:KeyWrapAlgorithm>http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p</trust:KeyWrapAlgorithm>\n" +
                        "                        <trust:EncryptWith>http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p</trust:EncryptWith>\n" +
                        "                        <trust:SignatureAlgorithm>http://www.w3.org/2000/09/xmldsig#rsa-sha1</trust:SignatureAlgorithm>\n" +
                        "                        <trust:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</trust:CanonicalizationAlgorithm>\n" +
                        "                        <trust:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</trust:EncryptionAlgorithm>\n" +
                        "                     </sp:RequestSecurityTokenTemplate>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:RequireInternalReference />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:IssuedToken>\n" +
                        "                  <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy />\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust13>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsp:Policy wsu:Id=\"IssuedTokenWSTrustBinding_IWSTrust13Async1_policy\">\n" +
                        "      <wsp:ExactlyOne>\n" +
                        "         <wsp:All>\n" +
                        "            <sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:TransportToken>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:HttpsToken />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:TransportToken>\n" +
                        "                  <sp:AlgorithmSuite>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Basic256 />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:AlgorithmSuite>\n" +
                        "                  <sp:Layout>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:Strict />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:Layout>\n" +
                        "                  <sp:IncludeTimestamp />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:TransportBinding>\n" +
                        "            <sp:EndorsingSupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:IssuedToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                     <sp:RequestSecurityTokenTemplate>\n" +
                        "                        <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</trust:KeyType>\n" +
                        "                        <trust:KeySize>256</trust:KeySize>\n" +
                        "                        <trust:KeyWrapAlgorithm>http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p</trust:KeyWrapAlgorithm>\n" +
                        "                        <trust:EncryptWith>http://www.w3.org/2001/04/xmlenc#aes256-cbc</trust:EncryptWith>\n" +
                        "                        <trust:SignatureAlgorithm>http://www.w3.org/2000/09/xmldsig#hmac-sha1</trust:SignatureAlgorithm>\n" +
                        "                        <trust:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</trust:CanonicalizationAlgorithm>\n" +
                        "                        <trust:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</trust:EncryptionAlgorithm>\n" +
                        "                     </sp:RequestSecurityTokenTemplate>\n" +
                        "                     <wsp:Policy>\n" +
                        "                        <sp:RequireInternalReference />\n" +
                        "                     </wsp:Policy>\n" +
                        "                  </sp:IssuedToken>\n" +
                        "                  <sp:KeyValueToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never\" wsp:Optional=\"true\" />\n" +
                        "                  <sp:SignedParts>\n" +
                        "                     <sp:Header Name=\"To\" Namespace=\"http://www.w3.org/2005/08/addressing\" />\n" +
                        "                  </sp:SignedParts>\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:EndorsingSupportingTokens>\n" +
                        "            <sp:Wss11 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy />\n" +
                        "            </sp:Wss11>\n" +
                        "            <sp:Trust13 xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "               <wsp:Policy>\n" +
                        "                  <sp:MustSupportIssuedTokens />\n" +
                        "                  <sp:RequireClientEntropy />\n" +
                        "                  <sp:RequireServerEntropy />\n" +
                        "               </wsp:Policy>\n" +
                        "            </sp:Trust13>\n" +
                        "            <wsaw:UsingAddressing />\n" +
                        "         </wsp:All>\n" +
                        "      </wsp:ExactlyOne>\n" +
                        "   </wsp:Policy>\n" +
                        "   <wsdl:types>\n" +
                        "      <xsd:schema targetNamespace=\"http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice/Imports\">\n" +
                        "         <xsd:import schemaLocation=\"$params6\" namespace=\"http://schemas.microsoft.com/Message\" />\n" +
                        "         <xsd:import schemaLocation=\"$params5\" namespace=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" />\n" +
                        "         <xsd:import schemaLocation=\"$params4\" namespace=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" />\n" +
                        "      </xsd:schema>\n" +
                        "   </wsdl:types>\n" +
                        "   <wsdl:message name=\"IWSTrustFeb2005Async_TrustFeb2005IssueAsync_InputMessage\">\n" +
                        "      <wsdl:part name=\"request\" element=\"t:RequestSecurityToken\" />\n" +
                        "   </wsdl:message>\n" +
                        "   <wsdl:message name=\"IWSTrustFeb2005Async_TrustFeb2005IssueAsync_OutputMessage\">\n" +
                        "      <wsdl:part name=\"TrustFeb2005IssueAsyncResult\" element=\"t:RequestSecurityTokenResponse\" />\n" +
                        "   </wsdl:message>\n" +
                        "   <wsdl:message name=\"IWSTrust13Async_Trust13IssueAsync_InputMessage\">\n" +
                        "      <wsdl:part name=\"request\" element=\"trust:RequestSecurityToken\" />\n" +
                        "   </wsdl:message>\n" +
                        "   <wsdl:message name=\"IWSTrust13Async_Trust13IssueAsync_OutputMessage\">\n" +
                        "      <wsdl:part name=\"Trust13IssueAsyncResult\" element=\"trust:RequestSecurityTokenResponseCollection\" />\n" +
                        "   </wsdl:message>\n" +
                        "   <wsdl:portType name=\"IWSTrustFeb2005Async\">\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <wsdl:input wsaw:Action=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" message=\"tns:IWSTrustFeb2005Async_TrustFeb2005IssueAsync_InputMessage\" />\n" +
                        "         <wsdl:output wsaw:Action=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue\" message=\"tns:IWSTrustFeb2005Async_TrustFeb2005IssueAsync_OutputMessage\" />\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:portType>\n" +
                        "   <wsdl:portType name=\"IWSTrust13Async\">\n" +
                        "      <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "         <wsdl:input wsaw:Action=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" message=\"tns:IWSTrust13Async_Trust13IssueAsync_InputMessage\" />\n" +
                        "         <wsdl:output wsaw:Action=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal\" message=\"tns:IWSTrust13Async_Trust13IssueAsync_OutputMessage\" />\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:portType>\n" +
                        "   <wsdl:binding name=\"CustomBinding_IWSTrustFeb2005Async\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#CustomBinding_IWSTrustFeb2005Async_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"CertificateWSTrustBinding_IWSTrustFeb2005Async\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#CertificateWSTrustBinding_IWSTrustFeb2005Async_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"CertificateWSTrustBinding_IWSTrustFeb2005Async1\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#CertificateWSTrustBinding_IWSTrustFeb2005Async1_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"UserNameWSTrustBinding_IWSTrustFeb2005Async\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrustFeb2005Async_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrustFeb2005Async_TrustFeb2005IssueAsync_Input_policy\" />\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrustFeb2005Async_TrustFeb2005IssueAsync_output_policy\" />\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"UserNameWSTrustBinding_IWSTrustFeb2005Async1\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrustFeb2005Async1_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"CustomBinding_IWSTrustFeb2005Async1\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#CustomBinding_IWSTrustFeb2005Async1_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"IssuedTokenWSTrustBinding_IWSTrustFeb2005Async\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#IssuedTokenWSTrustBinding_IWSTrustFeb2005Async_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1\" type=\"tns:IWSTrustFeb2005Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#IssuedTokenWSTrustBinding_IWSTrustFeb2005Async1_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"TrustFeb2005IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"CustomBinding_IWSTrust13Async\" type=\"tns:IWSTrust13Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#CustomBinding_IWSTrust13Async_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"CertificateWSTrustBinding_IWSTrust13Async\" type=\"tns:IWSTrust13Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#CertificateWSTrustBinding_IWSTrust13Async_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"UserNameWSTrustBinding_IWSTrust13Async\" type=\"tns:IWSTrust13Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#UserNameWSTrustBinding_IWSTrust13Async_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"IssuedTokenWSTrustBinding_IWSTrust13Async\" type=\"tns:IWSTrust13Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#IssuedTokenWSTrustBinding_IWSTrust13Async_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:binding name=\"IssuedTokenWSTrustBinding_IWSTrust13Async1\" type=\"tns:IWSTrust13Async\">\n" +
                        "      <wsp:PolicyReference URI=\"#IssuedTokenWSTrustBinding_IWSTrust13Async1_policy\" />\n" +
                        "      <soap12:binding transport=\"http://schemas.xmlsoap.org/soap/http\" />\n" +
                        "      <wsdl:operation name=\"Trust13IssueAsync\">\n" +
                        "         <soap12:operation soapAction=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue\" style=\"document\" />\n" +
                        "         <wsdl:input>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:input>\n" +
                        "         <wsdl:output>\n" +
                        "            <soap12:body use=\"literal\" />\n" +
                        "         </wsdl:output>\n" +
                        "      </wsdl:operation>\n" +
                        "   </wsdl:binding>\n" +
                        "   <wsdl:service name=\"SecurityTokenService\">\n" +
                        "      <wsdl:port name=\"UserNameWSTrustBinding_IWSTrustFeb2005Async\" binding=\"tns:UserNameWSTrustBinding_IWSTrustFeb2005Async\">\n" +
                        "         <soap12:address location=\"$params1\" />\n" +
                        "         <wsa10:EndpointReference>\n" +
                        "            <wsa10:Address>$params1</wsa10:Address>\n" +
                        "            <Identity xmlns=\"http://schemas.xmlsoap.org/ws/2006/02/addressingidentity\">\n" +
                        "               <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                        "                  <X509Data>\n" +
                        "                     <X509Certificate>$params3</X509Certificate>\n" +
                        "                  </X509Data>\n" +
                        "               </KeyInfo>\n" +
                        "            </Identity>\n" +
                        "         </wsa10:EndpointReference>\n" +
                        "      </wsdl:port>\n" +
                        "      <wsdl:port name=\"UserNameWSTrustBinding_IWSTrustFeb2005Async1\" binding=\"tns:UserNameWSTrustBinding_IWSTrustFeb2005Async1\">\n" +
                        "         <soap12:address location=\"$params1\" />\n" +
                        "         <wsa10:EndpointReference>\n" +
                        "            <wsa10:Address>$params1</wsa10:Address>\n" +
                        "         </wsa10:EndpointReference>\n" +
                        "      </wsdl:port>\n" +
                        "      <wsdl:port name=\"CustomBinding_IWSTrustFeb2005Async1\" binding=\"tns:CustomBinding_IWSTrustFeb2005Async1\">\n" +
                        "         <soap12:address location=\"$params2\" />\n" +
                        "         <wsa10:EndpointReference>\n" +
                        "            <wsa10:Address>$params2</wsa10:Address>\n" +
                        "         </wsa10:EndpointReference>\n" +
                        "      </wsdl:port>\n" +
                        "      <wsdl:port name=\"CustomBinding_IWSTrust13Async\" binding=\"tns:CustomBinding_IWSTrust13Async\">\n" +
                        "         <soap12:address location=\"$params2\" />\n" +
                        "         <wsa10:EndpointReference>\n" +
                        "            <wsa10:Address>$params2</wsa10:Address>\n" +
                        "         </wsa10:EndpointReference>\n" +
                        "      </wsdl:port>\n" +
                        "      <wsdl:port name=\"UserNameWSTrustBinding_IWSTrust13Async\" binding=\"tns:UserNameWSTrustBinding_IWSTrust13Async\">\n" +
                        "         <soap12:address location=\"$params1\" />\n" +
                        "         <wsa10:EndpointReference>\n" +
                        "            <wsa10:Address>$params1</wsa10:Address>\n" +
                        "         </wsa10:EndpointReference>\n" +
                        "      </wsdl:port>\n" +
                        "   </wsdl:service>\n" +
                        "</wsdl:definitions>";

                response = response.replace("$params1", stsEndpointUrl);
                response = response.replace("$params2", kerbosEndpointUrl);
                response = response.replace("$params3", encodedCertificate);
                response = response.replace("$params4", mexXSD0);
                response = response.replace("$params5", mexXSD1);
                response = response.replace("$params6", mexXSD2);


                OMElement omBody = AXIOMUtil.stringToOM(response);

                if (log.isDebugEnabled()) {
                        log.debug("Mex-Response => " + response);

                }

                return omBody;

        }

}




