#!/bin/bash
mv ./dropins/* ../repository/components/dropins/
mv ./deployment-client-modules/* ../repository/deployment/client/modules/
mv ./deployment-server-webapps/mexut.war ../repository/deployment/server/webapps/
mkdir ../repository/deployment/server/webapps/mex/
mv ./deployment-server-webapps/metadata.xml ../repository/deployment/server/webapps/mex/
