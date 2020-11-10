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

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

class HTTPSRuleTest {

    HTTPSRule httpsRule;

    @BeforeEach
    void setup() {
        httpsRule = new HTTPSRule();
    }

    @Test
    void getName() {
        assertEquals("HTTPS", httpsRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals(
                String.format(
                        "The HTTP message going to %s is not secure.", httpsRule.getMyAppName()),
                httpsRule.getDescription());
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg =
                new HttpMessage(
                        new URI(String.format("http://%s/", httpsRule.getMyAppName()), true));
        return msg;
    }

    private HttpMessage createNonMyAppHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    // The case in which there the domain is myAPP and it is HTTP message is secure
    @Test
    void isMyAppSecureViolated() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createHttpMsg();
        msg.setResponseHeader("HTTP/1.1 200 Connection established");
        msg.getRequestHeader().setSecure(true);
        assertFalse(httpsRule.isViolated(msg));
    }

    // The case in which there the domain is myAPP and HTTP message is not secure
    @Test
    void isMyAppNotSecureViolated() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createHttpMsg();
        msg.setResponseHeader("HTTP/1.1 200 Connection established");
        assertTrue(httpsRule.isViolated(msg));
    }

    // The case in which there the domain is myAPP and HTTP message is not secure
    @Test
    void isNotMyAppSecureViolated() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createNonMyAppHttpMsg();
        msg.setResponseHeader("HTTP/1.1 200 Connection established");
        msg.getRequestHeader().setSecure(true);
        assertFalse(httpsRule.isViolated(msg));
    }

    // The case in which there the domain is myAPP and HTTP message is not secure
    @Test
    void isNotMyAppViolated() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createNonMyAppHttpMsg();
        msg.setResponseHeader("HTTP/1.1 200 Connection established");
        assertFalse(httpsRule.isViolated(msg));
    }
}
