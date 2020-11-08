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

class CookieAttrRuleTest {
    CookieAttrRule cookieRule;

    @BeforeEach
    void setup() {
        cookieRule = new CookieAttrRule();
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    @Test
    void getName() {
        assertEquals("Cookie_Attribute_Rule", cookieRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals("Msg has certain attributes in Cookie", cookieRule.getDescription());
    }

    @Test
    void isViolatedAllPresent() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgF = createHttpMsg();
        msgF.setCookieParamsAsString("HttpOnly; Secure; SameSite=None");
        assertFalse(cookieRule.isViolated(msgF));
    }

    @Test
    void isViolatedHttpOnlyAbsent() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setCookieParamsAsString(" Secure; SameSite=Strict");
        assertTrue(cookieRule.isViolated(msgT));
    }

    @Test
    void isViolatedSecureAbsent() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setCookieParamsAsString(" HttpOnly; SameSite=Lax");
        assertTrue(cookieRule.isViolated(msgT));
    }

    @Test
    void isViolatedSameSiteAbsent() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setCookieParamsAsString(" HttpOnly; Secure");
        assertTrue(cookieRule.isViolated(msgT));
    }

    @Test
    void isViolatedAllMissing() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgT = createHttpMsg();
        msgT.setCookieParamsAsString("");
        assertTrue(cookieRule.isViolated(msgT));
    }

    @Test
    void isViolatedDiffOrder() throws HttpMalformedHeaderException, URIException {
        HttpMessage msgF = createHttpMsg();
        msgF.setCookieParamsAsString("D1=value; Secure; D2=value; SameSite=None; HttpOnly");
        assertFalse(cookieRule.isViolated(msgF));
    }
}
