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

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static org.junit.jupiter.api.Assertions.*;

class EmailMatchingRuleTest {

    EmailMatchingRule emailRule;

    @BeforeEach
    void setup() {
        emailRule = new EmailMatchingRule();
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.imdb.com/", true));
        return msg;
    }

    @Test
    void getName() {
        assertEquals("Email_matching_rule", emailRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals("The HTTP message contains an email address.", emailRule.getDescription());
    }

    @Test
    void isViolatedEmpty() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgF = createHttpMsg();
        msgF.setRequestBody("");
        msgF.setResponseBody("");
        assertFalse(emailRule.isViolated(msgF));
    }

    @Test
    void isViolatedSeparate() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setRequestBody("lucas");
        msgT.setResponseBody("@gmail.com");
        assertTrue(emailRule.isViolated(msgT));
    }

    @Test
    void isViolatedReq() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setRequestBody("lucas@gmail.com");
        msgT.setResponseBody("");
        assertTrue(emailRule.isViolated(msgT));
    }

    @Test
    void isViolatedRes() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setRequestBody("");
        msgT.setResponseBody("lucas@gmail.com");
        assertTrue(emailRule.isViolated(msgT));
    }

    @Test
    void isViolatedWrong() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setRequestBody("");
        msgT.setResponseBody("lucas@.com");
        assertFalse(emailRule.isViolated(msgT));
    }

    @Test
    void isViolatedNoName() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setRequestBody("");
        msgT.setResponseBody("@gmail.com");
        assertFalse(emailRule.isViolated(msgT));
    }
}
