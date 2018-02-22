package org.wso2.carbon.identity.sts.passive.ui.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class PassiveSTSHttpServletRequestWrapper extends HttpServletRequestWrapper {

    private final Map<String, String[]> parameters;

    public PassiveSTSHttpServletRequestWrapper(HttpServletRequest request) {

        super(request);
        parameters = new HashMap<String, String[]>(request.getParameterMap());
    }

    @Override
    public Map<String, String[]> getParameterMap() {

        return Collections.unmodifiableMap(parameters);
    }

    public void addParameter(String key, String value) {

        parameters.put(key, new String[]{value});
    }
}
