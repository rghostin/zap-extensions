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

/**
 * Rule to flag hidden inputs with name password that are to be submitted
 * to different domain from the one that responded
 */
public class HiddenFieldRule implements Rule {
    private static final List<String> FLAGGED_NAMES = Arrays.asList("password", "pwd", "pword", "token");
    private static final Pattern ACTION_FORM =
        Pattern.compile("<\\s*form\\s+action=\\\"(.*?)\\\".*?>((.|\\s)*?)<\\/form>");
    private static final Pattern HIDDEN_INPUT =
            Pattern.compile("<\\s*input\\s+type=\\\"hidden\\\".*?>");
    private static final Pattern NAME_HIDDEN_INPUT =
            Pattern.compile("<\\s*input.*?name=\\\"(.*?)\\\".*?>");

    @Override
    public String getName() {
        return "Hidden Field Rule";
    }

    @Override
    public String getDescription() {
        return "Check if Hidden Field ever sent to different domain";
    }

    /**
     * Checks whether an input with the given name should be inspected
     * @param name : the name of the input
     * @return : true if it should be inspected else false
     */
    public boolean isFlagged(String name) {
        return FLAGGED_NAMES.contains(name);
    }


    /**
     * Inspects a http response message and saves hidden fields name:value to hiddenFields Map
     * @param msg : the http message for which the response body needs inspection
     * @return
     */
    @Override
    public Violation checkViolation(HttpMessage msg) {
        String currentDomain = msg.getRequestHeader().getHostName();
        String httpResponseBody = msg.getResponseBody().toString();
        Matcher matcherAction = ACTION_FORM.matcher(httpResponseBody);
        String formDomain = "";

        // match a form in the body
        while(matcherAction.find()) {

            formDomain = matcherAction.group(1);
            String formBody = matcherAction.group(2);
            Matcher matcherHiddenInput = HIDDEN_INPUT.matcher(formBody);

            // match any hidden input in the form
            while (matcherHiddenInput.find()) {

                String inputStr = matcherHiddenInput.group().trim();

                // if it is for the specified name
                Matcher nameInputMatcher = NAME_HIDDEN_INPUT.matcher(inputStr);
                if (nameInputMatcher.find()) {

                    String name = nameInputMatcher.group(1);
                    if (isFlagged(name)) {
                        // if not form response domain - violation detected
                        if ( ! formDomain.equals(currentDomain)) {
                            return new Violation(
                                    getName(),
                                    getDescription(),
                                    msg,
                                    Arrays.asList(msg));
                        }
                    }
                }
            }
        }
        return null;
    }
}
