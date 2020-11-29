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
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;

/**
 * This is a rule for checking whether the HTTP response message contains the common response
 * headers present in previous requests
 */
public class CommonHeadersRule implements Rule {

    private final int BUFFER_SIZE = 5;

    private List<HttpResponseHeader> httpResponseHeaderContainer = new ArrayList<>();
    private List<HttpMessage> HTTP_MESSAGE_COMMON_HEADER = new ArrayList<>();

    @Override
    public String getName() {
        return "Common_Headers_Rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP response message does not contain common response header "
                + "present in previous requests.";
    }

    public List<HttpResponseHeader> getHttpResponseHeaderContainer() {
        return httpResponseHeaderContainer;
    }

    /**
     * Returns the common headers of the messages stored in the buffer
     *
     * @return common headers of previous requests
     */
    private List<HttpHeaderField> getCommonHeaderFields() {
        Map<HttpHeaderField, Integer> field_times = new HashMap<>();
        List<HttpHeaderField> commonHeaderFields = new ArrayList<>();

        for (HttpResponseHeader httpResponseHeader : httpResponseHeaderContainer) {
            List<HttpHeaderField> headers = httpResponseHeader.getHeaders();
            for (HttpHeaderField header : headers) {

                if (!field_times.keySet().contains(header)) {
                    // If not contain header
                    field_times.put(header, 0);
                } else {
                    // If contain header
                    field_times.put(header, field_times.get(header) + 1);
                }
            }
        }

        for (Map.Entry<HttpHeaderField, Integer> entry : field_times.entrySet()) {
            if (entry.getValue() == BUFFER_SIZE) {
                commonHeaderFields.add(entry.getKey());
            }
        }

        return commonHeaderFields;
    }

    /**
     * Checks whether a given http response message contains all the specified headers
     *
     * @param msg the HttpMessage that will be checked
     * @param headersToCheck the common headers needed to be checked with the HttpMessage
     * @return true if the HttpMessage contains all the specified the headers, false if not
     */
    private boolean containsAllHeaders(HttpMessage msg, List<HttpHeaderField> headersToCheck) {
        List<HttpHeaderField> headers = msg.getResponseHeader().getHeaders();
        for (HttpHeaderField headerToCheck : headersToCheck) {
            if (!headers.contains(headerToCheck)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Update the buffer for the httpResponseHeaderContainer
     *
     * @param newHeader the HttpResponseHeader that will be updated to the container
     */
    private void updateBufferWith(HttpResponseHeader newHeader) {
        httpResponseHeaderContainer.remove(0);
        httpResponseHeaderContainer.add(newHeader);
    }

    /**
     * Checks whether the HttpMessage violates the CommentHeaders rule rule or not
     *
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public Violation checkViolation(HttpMessage msg) {
        if (httpResponseHeaderContainer.size() != BUFFER_SIZE) {
            httpResponseHeaderContainer.add(msg.getResponseHeader());
            return null;
        }

        boolean isViolatedAttribute = false;

        // checks violation
        List<HttpHeaderField> commonHeaderFields = getCommonHeaderFields();
        if (!containsAllHeaders(msg, commonHeaderFields)) {
            isViolatedAttribute = true;
        }

        // update buffer
        updateBufferWith(msg.getResponseHeader());

        if (!isViolatedAttribute) {
            return null;
        } else {
            HTTP_MESSAGE_COMMON_HEADER.add(msg);
            return new Violation(getName(), getDescription(), msg, HTTP_MESSAGE_COMMON_HEADER);
        }
    }
}
