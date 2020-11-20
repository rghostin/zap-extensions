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
package org.zaproxy.zap.extension.dslpolicyloader;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.function.Predicate;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.exceptions.SyntaxErrorException;
import org.zaproxy.zap.extension.dslpolicyloader.parser.StatementParser;

class RuleTest {

    private List<String> getTestStatements() {
        return new ArrayList<>(
                Arrays.asList(
                        "request.header.re=\"test\" or response.body.value=\"test2\" and ( request.header.values=[\"ada\",\"wfww\"] or not response.body.value=\"test4\")",
                        "request.header.re=\"test\" or response.body.value=\"test2\"",
                        "request.header.values=[\"ada\",\"wfww\"]",
                        "not not request.header.values=[\"ada\",\"wfww\"]"));
    }

    private List<HttpMessage> hardCodingTestTrue()
            throws URIException, HttpMalformedHeaderException {
        List<HttpMessage> msgs = new ArrayList<>();
        HttpMessage msg1 = new HttpMessage(new URI("http://example.com/", true));
        msg1.setCookieParamsAsString("[\"ada\",\"wfww\"]");
        msg1.setResponseBody("test2");

        HttpMessage msg3 = new HttpMessage(new URI("http://example.com/", true));
        msg3.setResponseBody("test2");

        HttpMessage msg4 = new HttpMessage(new URI("http://adawfww.com/", true));

        HttpMessage msg5 = new HttpMessage(new URI("http://adawfww.com/", true));

        msgs.add(msg1);
        msgs.add(msg3);
        msgs.add(msg4);
        msgs.add(msg5);

        return msgs;
    }

    private List<HttpMessage> hardCodingTestFalse()
            throws URIException, HttpMalformedHeaderException {
        List<HttpMessage> msgs = new ArrayList<>();
        HttpMessage msg1 = new HttpMessage(new URI("http://example.com/", true));

        HttpMessage msg3 = new HttpMessage(new URI("http://example.com/", true));
        msg3.setResponseBody("test3");

        HttpMessage msg4 = new HttpMessage(new URI("http://aawww.com/", true));

        HttpMessage msg5 = new HttpMessage(new URI("http://aafww.com/", true));

        msgs.add(msg1);
        msgs.add(msg3);
        msgs.add(msg4);
        msgs.add(msg5);

        return msgs;
    }

    @Test
    void getName() {
        Rule rule = new Rule("Test", "Test Rule", null);
        assertEquals("Test", rule.getName());
    }

    @Test
    void getDescription() {
        Rule rule = new Rule("Test", "Test Rule", null);
        assertEquals("Test Rule", rule.getDescription());
    }

    @Test
    void isViolated() throws HttpMalformedHeaderException, URIException {
        List<String> tests = getTestStatements();
        List<HttpMessage> true_msgs = hardCodingTestTrue();
        List<HttpMessage> false_msgs = hardCodingTestFalse();

        Iterator<String> it_test = tests.iterator();
        Iterator<HttpMessage> it_httpmsgT = true_msgs.iterator();
        Iterator<HttpMessage> it_httpmsgF = false_msgs.iterator();

        while (it_test.hasNext() && it_httpmsgT.hasNext() && it_httpmsgF.hasNext()) {
            StatementParser sp_test = new StatementParser(it_test.next());
            Predicate<HttpMessage> predicate;
            Rule rule = null;
            try {
                predicate = sp_test.parse();
                rule = new Rule("Test", "Test Rule", predicate);
            } catch (SyntaxErrorException e) {
                fail("Unexpected syntax error");
            }

            HttpMessage temp_httpT = it_httpmsgT.next();
            HttpMessage temp_httpF = it_httpmsgF.next();

            assertTrue(rule.isViolated(temp_httpT));
            assertFalse(rule.isViolated(temp_httpF));
        }
    }
}
