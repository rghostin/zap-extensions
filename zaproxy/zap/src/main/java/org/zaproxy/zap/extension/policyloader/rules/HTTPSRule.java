/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is a rule for returning whether the traffic goes over HTTPS
 */
public class HTTPSRule implements Rule {

    private final String MY_APP_HOST = "cern.ch";

    private Pattern reMyappDomain = Pattern.compile(
            "^(?:[a-z0-9]+[.])*" + MY_APP_HOST + "$",
            Pattern.CASE_INSENSITIVE
        );

    @Override
    public String getName() {
        return "HTTPS";
    }
    @Override
    public String getDescription() {
        return String.format("The HTTP message going to %s is not secure.", MY_APP_HOST);
    }

    /**
     * Checks whether the hostname in message whether matches
     * @param msg the HttpMessage that will be checked
     * @return true if the hostname matches, false if not
     */
    private boolean isGoingToMyApp(HttpMessage msg) {
        String outgoingHostname = msg.getRequestHeader().getHostName();
        Matcher matcher = reMyappDomain.matcher(outgoingHostname);
        return matcher.matches();
    }

    /**
     * Checks whether the HttpMessage violates the HTTPS rule or not
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {
        if (isGoingToMyApp(msg)) {
            return ! msg.getRequestHeader().isSecure();
        }
        return false;
    }
}
