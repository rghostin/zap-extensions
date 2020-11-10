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
package org.zaproxy.zap.extension.policyloader.rules;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

class KeywordMatchingRuleTest {
    KeywordMatchingRule kwordRule;
    String BODY = "<html><head></head><body>%s</body><html>";

    @BeforeEach
    void setup() {
        kwordRule = new KeywordMatchingRule();
    }

    @Test
    void getName() {
        assertEquals("Keyword_matching_rule", kwordRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals("The HTTP message contains a flagged keyword.", kwordRule.getDescription());
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    private List<String> getPreGeneratedRandomString() {
        return new ArrayList<>(
                Arrays.asList(
                        "HdLw7thzug1qeEi",
                        "IkyF0U60BCQwulo",
                        "IDluIxJUEVh92XV",
                        "qey1Uehu2kuN9zL",
                        "oauuKUGcphrf2g9",
                        "fMWhQVd7ZguOLLp",
                        "hTn6mdE47Jl2mn9",
                        "Of9CsK2GYpM3DD7",
                        "3lLerf2oIVWdQGy",
                        "5CQftcNPn1ID9Wb"));
    }

    @Test
    void isViolatedFlaggedKeywords() throws HttpMalformedHeaderException, URIException {

        for (String kword : kwordRule.getFlaggedKeywords()) {
            HttpMessage msg = createHttpMsg();
            msg.setRequestBody(String.format(BODY, kword));
            assertTrue(kwordRule.isViolated(msg));
        }
    }

    @Test
    void isViolatedUnflaggedKeywords() throws HttpMalformedHeaderException, URIException {
        for (String kword : getPreGeneratedRandomString()) {
            HttpMessage msg = createHttpMsg();
            msg.setRequestBody(String.format(BODY, kword));
            assertFalse(kwordRule.isViolated(msg));
        }
    }
}
