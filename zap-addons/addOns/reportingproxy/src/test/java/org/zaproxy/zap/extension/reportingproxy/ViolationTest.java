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
package org.zaproxy.zap.extension.reportingproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

class ViolationTest {
    class TestRule implements Rule {

        @Override
        public String getName() {
            return "Test Rule Name";
        }

        @Override
        public String getDescription() {
            return "Test Rule Description";
        }

        @Override
        public Violation checkViolation(HttpMessage msg) {
            return null;
        }
    }

    @Test
    void getTitle() throws HttpMalformedHeaderException, URIException {
        TestRule testRule = new TestRule();
        HttpMessage msg = createHttpMsg();
        Violation violation =
                new Violation(testRule.getName(), testRule.getDescription(), msg, null);

        assertEquals(violation.getTitle(), String.format("Rule_%s violated", testRule.getName()));
    }

    @Test
    void getTriggeringUri() throws HttpMalformedHeaderException, URIException {
        TestRule testRule = new TestRule();
        HttpMessage msg = createHttpMsg();
        Violation violation =
                new Violation(testRule.getName(), testRule.getDescription(), msg, null);

        assertEquals(violation.getTriggeringUri(), msg.getRequestHeader().getURI().toString());
    }

    @Test
    void getEvidenceMessages() throws HttpMalformedHeaderException, URIException {
        TestRule testRule = new TestRule();

        HttpMessage msg = createHttpMsg();

        List<HttpMessage> msgs = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            msgs.add(createHttpMsg());
        }

        Violation violation =
                new Violation(testRule.getName(), testRule.getDescription(), msg, msgs);

        assertEquals(violation.getEvidenceMessages(), msgs);
    }

    @Test
    void getEvidenceUris() throws HttpMalformedHeaderException, URIException {
        TestRule testRule = new TestRule();
        HttpMessage msg = createHttpMsg();

        List<HttpMessage> msgs = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            msgs.add(createHttpMsg());
        }

        Violation violation =
                new Violation(testRule.getName(), testRule.getDescription(), msg, msgs);
        assertEquals(violation.getEvidenceMessages(), msgs);

        StringBuilder uris = new StringBuilder();
        for (HttpMessage msg_ : msgs) {
            uris.append(msg_.getRequestHeader().getURI().toString()).append('\n');
        }
        assertEquals(violation.getEvidenceUris(), uris.toString());
    }

    private List<TestRule> getTestRules() {
        TestRule testRule = new TestRule();
        return new ArrayList<TestRule>(Arrays.asList(testRule));
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        return new HttpMessage(new URI("http://example.com/", true));
    }

    @Test
    void getRuleName() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createHttpMsg();
        for (TestRule testRule : getTestRules()) {
            Violation violation =
                    new Violation(testRule.getName(), testRule.getDescription(), msg, null);
            assertEquals(testRule.getName(), violation.getRuleName());
        }
    }

    @Test
    void getDescription() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createHttpMsg();
        for (TestRule testRule : getTestRules()) {
            Violation violation =
                    new Violation(testRule.getName(), testRule.getDescription(), msg, null);
            assertEquals(testRule.getDescription(), violation.getDescription());
        }
    }

    @Test
    void getTriggeringMsg() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createHttpMsg();
        for (TestRule testRule : getTestRules()) {
            Violation violation =
                    new Violation(testRule.getName(), testRule.getDescription(), msg, null);
            assertEquals(msg, violation.getTriggeringMsg());
        }
    }
}
