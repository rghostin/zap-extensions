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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

public class ExpectCTRule implements Rule {

    private final String EXPECT_HEADER_NAME = "Expect-CT";
    private final Pattern expectPattern = Pattern.compile("max-age=(\\d+)");
    private final String MY_APP_HOST = "cern.ch";

    private Pattern reMyappDomain =
            Pattern.compile("^(?:[a-z0-9]+[.])*" + MY_APP_HOST + "$", Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() {
        return "ExpectCT_Rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP response message does not enforce ExpectCT Rule.";
    }

    private boolean isGoingToMyApp(HttpMessage msg) {
        String outgoingHostname = msg.getRequestHeader().getHostName();
        Matcher matcher = reMyappDomain.matcher(outgoingHostname);
        return matcher.matches();
    }

    @Override
    public boolean isViolated(HttpMessage msg) {
        if (isGoingToMyApp(msg)) {
            String expectHeader = msg.getResponseHeader().getHeader(EXPECT_HEADER_NAME);
            if (expectHeader == null) {
                return true;
            }
            expectHeader = expectHeader.trim();
            Matcher expectMatcher = expectPattern.matcher(expectHeader);
            if (!expectMatcher.find()) {
                return true;
            }
        }
        return false;
    }
}
