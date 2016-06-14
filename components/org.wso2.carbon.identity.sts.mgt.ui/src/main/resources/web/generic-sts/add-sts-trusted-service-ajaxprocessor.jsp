<%--
  ~ Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~  WSO2 Inc. licenses this file to you under the Apache License,
  ~  Version 2.0 (the "License"); you may not use this file except
  ~  in compliance with the License.
  ~  You may obtain a copy of the License at
  ~
  ~    http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.identity.sts.mgt.ui.client.CarbonSTSClient" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>

<%
    String httpMethod = request.getMethod();
    if (!"post".equalsIgnoreCase(httpMethod)) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
    }

    String spName = request.getParameter("spName");
    String action = request.getParameter("spAction");

    try {

        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
        CarbonSTSClient stsClient = new CarbonSTSClient(config, session, cookie);

        String address = request.getParameter("endpointaddrs");
        String keyAlias = request.getParameter("alias");

        stsClient.addTrustedService(address, keyAlias);
        if (spName != null && action != null && "returnToSp".equals(action)) {

            boolean applicationComponentFound = CarbonUIUtil.isContextRegistered(config, "/application/");
            if (applicationComponentFound) {
%>
<script>
    location.href = '../application/configure-service-provider.jsp?action=update&display=serviceName&spName=<%=Encode.forUriComponent(spName)%>&serviceName=<%=Encode.forUriComponent(address)%>';
</script>
<%
} else {
%>
<script>
    location.href = 'sts.jsp';
</script>
<%
        }
    }
} catch (Exception e) {
%>
<script>
    <jsp:forward page="../admin/error.jsp?<%=e.getMessage()%>"/>
</script>
<%
        return;
    }
%>