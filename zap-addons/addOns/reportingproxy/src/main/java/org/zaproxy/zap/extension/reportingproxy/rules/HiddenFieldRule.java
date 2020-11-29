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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;
import org.zaproxy.zap.extension.reportingproxy.utils.Pair;

public class HiddenFieldRule implements Rule {

    // Map< (Name, Value), Domain>
    Map<Pair<String, String>, String> hiddenFields = new HashMap<>();
    // Map <(Name, Value), HttpMessage>
    Map<Pair<String, String>, HttpMessage> messageHistory = new HashMap<>();

    private final Pattern INPUT_LINE = Pattern.compile("<\\s*input.*?>");
    private final Pattern HIDDEN_LINE = Pattern.compile("<\\s*input\\s+type=\\\"hidden\\\".*?>");
    private final Pattern NAME_HIDDEN_LINE = Pattern.compile("<\\s*input.*?name=\\\"(.*?)\\\".*?>");
    private final Pattern NAME_HIDDEN_VALUE =
            Pattern.compile("<\\s*input.*?value=\\\"(.*?)\\\".*?>");

    @Override
    public String getName() {
        return "Hidden Field Rule";
    }

    @Override
    public String getDescription() {
        return "Check if Hidden Field ever sent to different domain";
    }

    // todo rm
    private void printMap(boolean isviolated) {
        System.out.println("Isviolated: "+isviolated);
        for (Map.Entry<Pair<String, String>, String> entry : hiddenFields.entrySet()) {
            System.out.println(entry.getKey().first + "," + entry.getKey().second + ":" + entry.getValue());
        }
    }

    // todo split into methods and javadoc
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

            Matcher matcherValue = NAME_HIDDEN_VALUE.matcher(inputStr);
            String value = "";
            if (matcherValue.matches()) {
                value = matcherValue.group(1);
            }
            Pair<String, String> inputNameValuePair = new Pair<>(name, value);

            String outgoingHostname = msg.getRequestHeader().getHostName();
            if (!hiddenFields.containsKey(inputNameValuePair)) {
                hiddenFields.put(inputNameValuePair, outgoingHostname);
                messageHistory.put(inputNameValuePair, msg);
            } else {
                String domain = hiddenFields.get(inputNameValuePair);
                if (!domain.equals(outgoingHostname)) {
                    HttpMessage violatedMessage = messageHistory.get(inputNameValuePair);

                    printMap(true);
                    return new Violation(
                            getName(), getDescription(), msg, Arrays.asList(violatedMessage));
                }
            }
        }
        printMap(false);
        return null;
    }
}
