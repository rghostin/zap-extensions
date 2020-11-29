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

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;

// todo add tests
public class HiddenFieldRule implements Rule {

    Map<String, String> hiddenFields = new HashMap<>();

    private final Pattern INPUT_LINE = Pattern.compile("<\\s*input.*?>");
    private final Pattern HIDDEN_LINE = Pattern.compile("<\\s*input\\s+type=\\\"hidden\\\".*?>");
    private final Pattern NAME_HIDDEN_LINE = Pattern.compile("<\\s*input.*?name=\\\"(.*?)\\\".*?>");

    @Override
    public String getName() {
        return "Hidden Field Rule";
    }

    @Override
    public String getDescription() {
        return "Check if Hidden Field ever sent to different domain";
    }

    @Override
    public Violation checkViolation(HttpMessage msg) {
        String httpResponseBody = msg.getResponseBody().toString();
        Matcher matcherInput = INPUT_LINE.matcher(httpResponseBody);

        while (matcherInput.find()) {
            String inputStr = matcherInput.group().trim();

            // if it is hidden
            Matcher matcherHidden = HIDDEN_LINE.matcher(inputStr);
            if (!matcherHidden.find()) continue;

            // get its name
            Matcher matcherName = NAME_HIDDEN_LINE.matcher(inputStr);
            String name = "";
            if (matcherName.matches()) {
                name = matcherName.group(1);
            } else {
                continue;
            }

            String outgoingHostname = msg.getRequestHeader().getHostName();
            if (!hiddenFields.containsKey(name)) {
                hiddenFields.put(name, outgoingHostname);
            } else {
                String domain = hiddenFields.get(name);
                if (!domain.equals(outgoingHostname)) {
                    return new Violation(getName(), getDescription(), msg, null);
                }
            }
        }
        return null;
    }
}
