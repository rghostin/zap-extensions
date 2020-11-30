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
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;
import org.zaproxy.zap.extension.reportingproxy.utils.Pair;

public class HiddenFieldRule implements Rule {

    // Map< (Name, Value), Domain>
    Map<String, String> hiddenFields = new HashMap<>();
    // Map <(Name, Value), HttpMessage>
    Map<String, HttpMessage> messageHistory = new HashMap<>();

    private static final Pattern INPUT_LINE = Pattern.compile("<\\s*input.*?>");
    private static final Pattern ACTION_FROM =
            Pattern.compile("<\\s*from\\s+action=\\\"(.*?)\\\".*?>");
    private static final Pattern HIDDEN_LINE =
            Pattern.compile("<\\s*input\\s+type=\\\"hidden\\\".*?>");
    private static final Pattern NAME_HIDDEN_LINE =
            Pattern.compile("<\\s*input.*?name=\\\"(.*?)\\\".*?>");
    private static final Pattern NAME_HIDDEN_VALUE =
            Pattern.compile("<\\s*input.*?value=\\\"(.*?)\\\".*?>");

    @Override
    public String getName() {
        return "Hidden Field Rule";
    }

    @Override
    public String getDescription() {
        return "Check if Hidden Field ever sent to different domain";
    }

    /**
     * Given a body (string) extracts all the hidden fields with name and value
     *
     * @param body : the body
     * @return a list of pair<String, String> name:value of hidden fields
     */
    private static List<String> extractHiddenFields(String body) {

        List<String> fields = new ArrayList<>();

        Matcher matcherInput = INPUT_LINE.matcher(body);

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

//            Matcher matcherValue = NAME_HIDDEN_VALUE.matcher(inputStr);
//            String value = "";
//            if (matcherValue.matches()) {
//                value = matcherValue.group(1);
//            } else {
//                continue;
//            }
            fields.add(name);
        }

        return fields;
    }


    /**
     * Inspects a http response message and saves hidden fields name:value to hiddenFields Map
     * @param msg : the http message for which the response body needs inspection
     */
    private void saveHiddenFieldsFromResponse(HttpMessage msg) {
        String outgoingHostname = msg.getRequestHeader().getHostName();
        String httpResponseBody = msg.getResponseBody().toString();
        Matcher matcherInput = INPUT_LINE.matcher(httpResponseBody);
        List<String> extracted_hidden_Fields =
                extractHiddenFields(msg.getResponseBody().toString());
        for (String fieldPair : extracted_hidden_Fields) {
            if (!hiddenFields.containsKey(fieldPair)) {
                hiddenFields.put(fieldPair, outgoingHostname);
                messageHistory.put(fieldPair, msg);
            }
        }
    }

    /**
     * Checks for rule violation
     * For a given http message, if it is a get response, store the hidden fields
     * If it is a POST request checks whether previously known inputs are sent
     * @param msg the HttpMessage that will be checked
     * @return : Violation object if a violation occurs else null
     */
    @Override
    public Violation checkViolation(HttpMessage msg) {
        saveHiddenFieldsFromResponse(msg);

        // Check whether an outgoing POST request contains the name:value from another domain
        String outgoingHostname = msg.getRequestHeader().getHostName();

        if (msg.getRequestHeader().getMethod().equals("POST")) {
            for (HtmlParameter htmlParam : msg.getFormParams()) {
                if (htmlParam.getType() == HtmlParameter.Type.form) {
                    Pair<String, String> fieldPair =
                            new Pair<>(htmlParam.getName(), htmlParam.getValue());
                    if (hiddenFields.containsKey(fieldPair)) {
                        String registeredHostname = hiddenFields.get(fieldPair);
                        if (!registeredHostname.equals(outgoingHostname)) {
                            HttpMessage violatedMessage = messageHistory.get(fieldPair);
                            return new Violation(
                                    getName(),
                                    getDescription(),
                                    msg,
                                    Arrays.asList(violatedMessage));
                        }
                    }
                }
            }
        }
        return null;
    }
}
