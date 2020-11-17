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
package org.zaproxy.zap.extension.dslpolicyloader.predicate;

import static org.junit.jupiter.api.Assertions.*;

import java.util.function.Predicate;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

class HttpPredicateBuilderTest {

    HttpPredicateBuilder httpPredicateBuilder;

    @BeforeEach
    void setup() {
        httpPredicateBuilder = new HttpPredicateBuilder();
    }

    @Test
    void build() {
        Predicate<HttpMessage> predicate;
        Pattern pattern = Pattern.compile("abc", Pattern.CASE_INSENSITIVE);

        predicate = httpPredicateBuilder.build(TransmissionType.REQUEST, FieldType.BODY, pattern);
        assertTrue(predicate.test(createHttpMsg("Request", "", "abc")));

        predicate = httpPredicateBuilder.build(TransmissionType.RESPONSE, FieldType.BODY, pattern);
        assertTrue(predicate.test(createHttpMsg("Response", "", "abc")));

        predicate = httpPredicateBuilder.build(TransmissionType.REQUEST, FieldType.HEADER, pattern);
        assertTrue(predicate.test(createHttpMsg("Request", "abc", "")));

        predicate =
                httpPredicateBuilder.build(TransmissionType.RESPONSE, FieldType.HEADER, pattern);
        assertTrue(predicate.test(createHttpMsg("Response", "abc", "")));
    }

    private HttpMessage createHttpMsg(String transmission, String head, String body) {
        try {
            HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
            if ("Request".equals(transmission)) {
                if (!"".equals(head.trim())) {
                    msg.getRequestHeader().setHeader(head, head);
                } else if (!"".equals(body.trim())) {
                    msg.setRequestBody(
                            String.format("<html><head></head><body>%s</body><html>", body));
                }
            } else if ("Response".equals(transmission)) {
                if (!"".equals(head.trim())) {
                    msg.getResponseHeader().setHeader(head, head);
                } else if (!"".equals(body.trim())) {
                    msg.setResponseBody(
                            String.format("<html><head></head><body>%s</body><html>", body));
                }
            }
            return msg;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
