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

class DomainMatchingRuleTest {

    DomainMatchingRule domainRule;

    @BeforeEach
    void setup() {
        domainRule = new DomainMatchingRule();
    }

    private HttpMessage createHttpMsg(String url)
            throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI(url, true));
        return msg;
    }

    private List<String> getURLStringsCorrect() {
        return new ArrayList<>(
                Arrays.asList(
                        "www.google.com",
                        "www.zerohege.com",
                        "www.youtube.com",
                        "www.imd.com",
                        "http://www.cer.ch"));
    }

    private List<String> getURLStringsWrong() {
        return new ArrayList<>(
                Arrays.asList(
                        "www.zerohedge.com",
                        "http://www.imdb.com",
                        "www.cern.ch",
                        "www.zerohedge.com",
                        "www.imdb.com",
                        "www.cern.ch"));
    }

    @Test
    void getName() {
        assertEquals("Domain_matching_rule", domainRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals("The request is going to a flagged domain.", domainRule.getDescription());
    }

    @Test
    void isViolatedFalse() throws HttpMalformedHeaderException, URIException {
        for (String url : getURLStringsCorrect()) {
            HttpMessage msg = createHttpMsg(url);
            assertFalse(domainRule.isViolated(msg));
        }
    }

    @Test
    void isViolatedTrue() throws HttpMalformedHeaderException, URIException {
        for (String url : getURLStringsWrong()) {
            HttpMessage msg = createHttpMsg(url);
            assertTrue(domainRule.isViolated(msg));
        }
    }
}
