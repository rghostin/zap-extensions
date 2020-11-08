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

/** This is a rule for matching the generic email address format */
public class EmailMatchingRule implements Rule {

    private final String REGEX_EMAIL = "(.{1,64})@(.{1,255})\\.(.{1,24})";
    private Pattern pattern = Pattern.compile(REGEX_EMAIL);

    @Override
    public String getName() {
        return "Email_matching_rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP message contains an email address.";
    }

    /**
     * Checks whether the HttpMessage violates the email-matching rule or not
     *
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {
        String bodySend = msg.getRequestBody().toString();
        String bodyReceive = msg.getResponseBody().toString();
        String body = bodySend + bodyReceive;
        Matcher matcher = pattern.matcher(body);
        if (matcher.find()) {
            return true;
        }
        return false;
    }
}
