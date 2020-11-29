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
package org.zaproxy.zap.extension.reportingproxy.rules;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;

// todo rm
/** This is a rule for flagging bad keywords */
public class KeywordMatchingRule implements Rule {

    @Override
    public String getName() {
        return "Keyword_matching_rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP message contains a flagged keyword.";
    }

    /**
     * Returns the keywords to flag
     *
     * @return Returns the keywords to flag
     */
    public List<String> getFlaggedKeywords() {
        return new ArrayList<>(Arrays.asList("hacker", "phishing", "eavesdropping", "hacking"));
    }

    /**
     * Checks whether the HttpMessage violates the keyword-matching rule or not
     *
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public Violation checkViolation(HttpMessage msg) {
        String bodySend = msg.getRequestBody().toString();
        String bodyReceive = msg.getResponseBody().toString();
        String body = bodySend + bodyReceive;

        for (String keyword : getFlaggedKeywords()) {
            if (body.contains(keyword)) {
                return new Violation(getName(), getDescription(), msg, null);
            }
        }
        return null;
    }
}
