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
package org.zaproxy.zap.extension.dslpolicyloader.parser;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.Policy;
import org.zaproxy.zap.extension.dslpolicyloader.exceptions.SyntaxErrorException;

class PolicyParserTest {

    // Input for Rules
    private String policy_content =
            "Rule \"hacker_rule\" \"hacker exists in the response body\" : "
                    + "response.body.value=\"hacker\"; "
                    + "Rule \"zerohedge_rule\" \"zerohedge exists in the response body\": "
                    + "request.body.value=\"zerohedge\"";

    private List<HttpMessage> hardCodingTestTrue()
            throws URIException, HttpMalformedHeaderException {
        List<HttpMessage> msgs = new ArrayList<>();
        HttpMessage msg1 = new HttpMessage(new URI("http://example.com/", true));
        msg1.setResponseBody("hacker");

        HttpMessage msg2 = new HttpMessage(new URI("http://example.com/", true));
        msg2.setRequestBody("zerohedge");

        HttpMessage msg3 = new HttpMessage(new URI("http://adawfww.com/", true));
        msg3.setResponseBody("hacker");

        HttpMessage msg4 = new HttpMessage(new URI("http://adawfww.com/", true));
        msg4.setRequestBody("zerohedge");

        msgs.add(msg1);
        msgs.add(msg2);
        msgs.add(msg3);
        msgs.add(msg4);

        return msgs;
    }

    private List<HttpMessage> hardCodingTestFalse()
            throws URIException, HttpMalformedHeaderException {
        List<HttpMessage> msgs = new ArrayList<>();
        HttpMessage msg1 = new HttpMessage(new URI("http://example.com/", true));

        HttpMessage msg2 = new HttpMessage(new URI("http://example.com/", true));

        HttpMessage msg3 = new HttpMessage(new URI("http://aawww.com/", true));

        HttpMessage msg4 = new HttpMessage(new URI("http://aafww.com/", true));

        msgs.add(msg1);
        msgs.add(msg2);
        msgs.add(msg3);
        msgs.add(msg4);

        return msgs;
    }

    @Test
    void parsePolicy() throws SyntaxErrorException, HttpMalformedHeaderException, URIException {
        PolicyParser policyParser = new PolicyParser();
        List<HttpMessage> true_msgs = hardCodingTestTrue();
        List<HttpMessage> false_msgs = hardCodingTestFalse();

        Iterator<HttpMessage> it_httpmsgT = true_msgs.iterator();
        Iterator<HttpMessage> it_httpmsgF = false_msgs.iterator();
        Policy policy = policyParser.parsePolicy(policy_content, "test");

        while (it_httpmsgT.hasNext() && it_httpmsgF.hasNext()) {

            HttpMessage temp_httpT = it_httpmsgT.next();
            HttpMessage temp_httpF = it_httpmsgF.next();

            System.out.println(it_httpmsgT.toString());
            System.out.println(it_httpmsgF.toString());

            assertEquals(1, policy.checkViolations(temp_httpT).size());
            assertEquals(0, policy.checkViolations(temp_httpF).size());
        }
    }
}
