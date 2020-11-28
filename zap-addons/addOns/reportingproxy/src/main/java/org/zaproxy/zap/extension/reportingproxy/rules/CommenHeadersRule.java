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

import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.reportingproxy.Rule;

import java.util.*;
import java.util.regex.Pattern;

/** This is a rule for checking the HSTS header exist in the response HTTPMessage */
public class CommenHeadersRule implements Rule {
    private final int BUFFER_SIZE = 5;


    // HTTPResponseHeaders
    private List<HttpResponseHeader> httpMessagesContainer = new ArrayList<>();

    @Override
    public String getName() {
        return "Common_Headers_Rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP response message does not enforce HSTS.";
    }

    /**
     * Returns the common headers of the messages stored in the buffer
     * @return
     */
    private List<HttpHeaderField> getCommonHeaders() {
        // TODO
        return null;
    }

    /**
     * Checks whether a given http response message contains all the specified headers
     * @param msg
     * @param headersToCheck
     * @return
     */
    private boolean containsAllHeaders(HttpMessage msg, List<HttpHeaderField> headersToCheck) {
        // TODO
        return false;
    }

    // TODO comment
    public void updateBufferWith(HttpResponseHeader newHeader) {
        httpMessagesContainer.remove(0);
        httpMessagesContainer.add(newHeader);
    }

    /**
     * Checks whether the HttpMessage violates the HSTS rule rule or not
     *
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {

        if (httpMessagesContainer.size() != BUFFER_SIZE) {
            httpMessagesContainer.add(msg.getResponseHeader());
            return false;
        }

        boolean isViolatedAttribute = false;

        // checks violation
        List<HttpHeaderField> commonHeaderFields = getCommonHeaders();
        if (! containsAllHeaders(msg, commonHeaderFields)) {
            isViolatedAttribute = true;
        }

        // update buffer
        updateBufferWith(msg.getResponseHeader());

        return isViolatedAttribute;
    }

//    private boolean isResponseHttpHeadersEqual(List<StoreHttpMsg> storeHttpMsgs) {
//        Set<Map<String, String>> reponseHeadersContainer = new HashSet<>();
//        for (StoreHttpMsg storeHttpMsg : storeHttpMsgs) {
//            reponseHeadersContainer.add(storeHttpMsg.getResponseHeaders());
//        }
//        if (reponseHeadersContainer.size() != 5) {
//            return true;
//        } else {
//            return false;
//        }
//    }


}


