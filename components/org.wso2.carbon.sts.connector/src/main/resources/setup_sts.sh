#!/bin/bash
mv ./dropins/* ../repository/components/dropins/
mv ./deployment-client-modules/* ../repository/deployment/client/modules/

IS_HOME=".."

mv ./dropins/* "$IS_HOME"/repository/components/dropins/
mv ./deployment-client-modules/* "$IS_HOME"/repository/deployment/client/modules/

# ---------------------------------------------------------------------------
# Conditionally install not-yet-commons-ssl.
# Requires commons-httpclient >= 3.1.0.wso2v6_11 to be present as this is where
# not-yet-commons-ssl was removed from the pack.
# ---------------------------------------------------------------------------

MINIMUM_HTTPCLIENT_VERSION="3.1.0.wso2v6_11"

# Normalize version string for integer comparison.
# "3.1.0.wso2v6_11" -> "3 1 0 6 11"
version_normalize() {
    echo "$1" | sed 's/wso2v//' | tr '._-' ' '
}

# Returns 0 (true) when v1 >= v2.
version_gte() {
    local v1=( $(version_normalize "$1") )
    local v2=( $(version_normalize "$2") )
    local len="${#v2[@]}"
    for (( i=0; i<len; i++ )); do
        local p1="${v1[$i]:-0}"
        local p2="${v2[$i]:-0}"
        if (( 10#$p1 > 10#$p2 )); then return 0; fi
        if (( 10#$p1 < 10#$p2 )); then return 1; fi
    done
    return 0
}

HTTPCLIENT_JAR=$(find "$IS_HOME"/repository/components/plugins "$IS_HOME"/repository/components/dropins \
    -maxdepth 1 -name "commons-httpclient_*.jar" 2>/dev/null | sort -V | tail -1)

if [ -n "$HTTPCLIENT_JAR" ]; then
    INSTALLED_VERSION=$(basename "$HTTPCLIENT_JAR" .jar | sed 's/^commons-httpclient_//')
    if version_gte "$INSTALLED_VERSION" "$MINIMUM_HTTPCLIENT_VERSION"; then
        mv ./lib/not-yet-commons-ssl*.jar "$IS_HOME"/repository/components/dropins/
    fi
fi
