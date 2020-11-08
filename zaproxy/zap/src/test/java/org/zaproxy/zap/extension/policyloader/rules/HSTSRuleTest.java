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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HSTSRuleTest {

    HSTSRule hstsRule;

    @BeforeEach
    void setup() {
        hstsRule = new HSTSRule();
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    private List<String> getHSTSCorrect() {
        return new ArrayList<>(
                Arrays.asList(
                        "max-age=1",
                        "max-age=1;includeSubDomains",
                        "max-age=123456",
                        "max-age=123456 ; includeSubDomains",
                        "max-age=123456;includeSubDomains;preload"));
    }

    private List<String> getHSTSWrong() {
        return new ArrayList<>(
                Arrays.asList(
                        "max_age=1;",
                        "max-age=1a",
                        "max-age=1;include",
                        "max-age=1;includeSubDomains1",
                        "max-age=123456;includeSubDomains;;preload"));
    }

    @Test
    void getName() {
        assertEquals("HSTS_Rule", hstsRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals("The HTTP response message does not enforce HSTS.", hstsRule.getDescription());
    }

    @Test
    void isViolatedCorrect() throws HttpMalformedHeaderException, URIException {
        for (String val : getHSTSCorrect()) {
            HttpMessage msg = createHttpMsg();
            msg.getResponseHeader().setHeader("Strict-Transport-Security", val);
            assertFalse(hstsRule.isViolated(msg));
        }
    }

    @Test
    void isViolatedWrong() throws HttpMalformedHeaderException, URIException {
        for (String val : getHSTSWrong()) {
            HttpMessage msg = createHttpMsg();
            msg.getResponseHeader().setHeader("Strict-Transport-Security", val);
            assertTrue(hstsRule.isViolated(msg));
        }
    }
}
