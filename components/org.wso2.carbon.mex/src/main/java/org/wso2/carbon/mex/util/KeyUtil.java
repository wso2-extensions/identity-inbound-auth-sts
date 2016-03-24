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
package org.wso2.carbon.mex.util;


import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.mex.MexException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class KeyUtil {

    public static X509Certificate getCertificateToIncludeInMex
            (String serviceName) throws MexException, KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException {
        X509Certificate cert = null;

        // this is for UT token policy
        ServerConfiguration config = ServerConfiguration.getInstance();
        String path = new File(config.getFirstProperty("Security.KeyStore.Location")).getAbsolutePath();
        String password = config.getFirstProperty("Security.KeyStore.Password");
        String keyalias = config.getFirstProperty("Security.KeyStore.KeyAlias");
        String storeType = config.getFirstProperty("Security.KeyStore.Type");

        FileInputStream ksIn = new FileInputStream(path);
        BufferedInputStream ksbufin = new BufferedInputStream(ksIn);

        KeyStore store = KeyStore.getInstance(storeType);
        store.load(ksbufin, password.toCharArray());

        cert = (X509Certificate) store.getCertificate(keyalias);

        return cert;
    }
}
