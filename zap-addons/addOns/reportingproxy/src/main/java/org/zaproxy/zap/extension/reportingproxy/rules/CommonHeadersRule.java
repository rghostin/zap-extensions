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
import org.zaproxy.zap.extension.reportingproxy.utils.Pair;

/**
 * This is a rule for checking whether the HTTP response message contains the common response
 * headers present in previous requests
 */
public class CommonHeadersRule implements Rule {

    private final int BUFFER_SIZE = 5;

    private List<HttpMessage> httpMessageContainer = new ArrayList<>();

    @Override
    public String getName() {
        return "Common_Headers_Rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP response message does not contain common response header "
                + "present in previous requests.";
    }

    /**
     * Returns the common headers of the messages stored in the buffer
     *
     * @return common headers of previous requests
     */
    private List<Pair<String, String>> getCommonHeaderFields() {
        // Map( (HeaderName, HeaderValue) : numberOfOccurence )
        Map<Pair<String, String>, Integer> field_times = new HashMap<>();
        List<Pair<String, String>> commonHeaderFields = new ArrayList<>();
        List<HttpResponseHeader> httpResponseHeaderContainer = getHttpResponseHeaderContainer();

        for (HttpResponseHeader httpResponseHeader : httpResponseHeaderContainer) {
            List<HttpHeaderField> headerFields = httpResponseHeader.getHeaders();

            for (HttpHeaderField headerField : headerFields) {
                Pair<String, String> headerPair =
                        new Pair<>(headerField.getName(), headerField.getValue());
                if (!field_times.containsKey(headerPair)) {
                    // If not contain header
                    field_times.put(headerPair, 0);
                } else {
                    // If contain header
                    field_times.put(headerPair, field_times.get(headerPair) + 1);
                }
            }
        }

        for (Map.Entry<Pair<String, String>, Integer> entry : field_times.entrySet()) {
            if (entry.getValue() == BUFFER_SIZE - 1) {
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
    private boolean containsAllHeaders(HttpMessage msg, List<Pair<String, String>> headersToCheck) {
        List<HttpHeaderField> headerFields = msg.getResponseHeader().getHeaders();
        List<Pair<String, String>> headers = new ArrayList<>();
        for (HttpHeaderField headerField : headerFields) {
            headers.add(new Pair<>(headerField.getName(), headerField.getValue()));
        }

        for (Pair<String, String> headerToCheck : headersToCheck) {
            if (!headers.contains(headerToCheck)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Updates the buffer for the httpResponseHeaderContainer
     *
     * @param msg the HttpResponseHeader that will be updated to the container
     */
    private void updateBufferWith(HttpMessage msg) {
        httpMessageContainer.remove(0);
        httpMessageContainer.add(msg);
    }

    /**
     * Returns the container of the response headers store in the current http message container
     *
     * @return List of response header stored in the http message container
     */
    public List<HttpResponseHeader> getHttpResponseHeaderContainer() {
        List<HttpResponseHeader> httpResponseHeaderContainer = new ArrayList<>();
        for (HttpMessage httpMessage : httpMessageContainer) {
            httpResponseHeaderContainer.add(httpMessage.getResponseHeader());
        }
        return httpResponseHeaderContainer;
    }

    /**
     * Checks whether the HttpMessage violates the CommentHeaders rule rule or not
     *
     * @param msg the HttpMessage that will be checked
     * @return Violation object if a violation occurs else null
     */
    @Override
    public Violation checkViolation(HttpMessage msg) {
        if (httpMessageContainer.size() != BUFFER_SIZE) {
            httpMessageContainer.add(msg);
            return null;
        }

        boolean isViolatedAttribute = false;

        // checks violation
        List<Pair<String, String>> commonHeaderFields = getCommonHeaderFields();
        if (!containsAllHeaders(msg, commonHeaderFields)) {
            isViolatedAttribute = true;
        }

        // update buffer
        updateBufferWith(msg);

        if (!isViolatedAttribute) {
            return null;
        } else {
            return new Violation(getName(), getDescription(), msg, httpMessageContainer);
        }
    }
}
