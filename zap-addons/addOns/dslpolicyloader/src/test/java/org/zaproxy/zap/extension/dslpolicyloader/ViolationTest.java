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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.predicate.HttpPredicateBuilder;

class ViolationTest {

    private List<Rule> getTestRules() {
        String testName = "Test Rule Name";
        String testDescription = "Test Rule Description";
        HttpPredicateBuilder predicateBuilder = new HttpPredicateBuilder();
        Predicate<HttpMessage> testPredicate = predicateBuilder.build(null, null, null);
        Rule testRule = new Rule(testName, testDescription, testPredicate);
        return new ArrayList<Rule>(Arrays.asList(testRule));
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    @Test
    void getPolicyName() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test Policy";
        HttpMessage msg = createHttpMsg();
        for (Rule testRule : getTestRules()) {
            Violation violation = new Violation(policyName, testRule, msg);
            assertEquals(policyName, violation.getPolicyName());
        }
    }

    @Test
    void getRuleName() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test Policy";
        HttpMessage msg = createHttpMsg();
        for (Rule testRule : getTestRules()) {
            Violation violation = new Violation(policyName, testRule, msg);
            assertEquals(testRule.getName(), violation.getRuleName());
        }
    }

    @Test
    void getDescription() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test Policy";
        HttpMessage msg = createHttpMsg();
        for (Rule testRule : getTestRules()) {
            Violation violation = new Violation(policyName, testRule, msg);
            assertEquals(testRule.getDescription(), violation.getDescription());
        }
    }

    @Test
    void getMsg() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test Policy";
        HttpMessage msg = createHttpMsg();
        for (Rule testRule : getTestRules()) {
            Violation violation = new Violation(policyName, testRule, msg);
            assertEquals(msg, violation.getMsg());
        }
    }

    @Test
    void getTitle() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test Policy";
        HttpMessage msg = createHttpMsg();
        for (Rule testRule : getTestRules()) {
            String testTitle =
                    String.format("Policy_%s.Rule_%s violated", policyName, testRule.getName());
            Violation violation = new Violation(policyName, testRule, msg);
            assertEquals(testTitle, violation.getTitle());
        }
    }

    @Test
    void getUri() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test Policy";
        HttpMessage msg = createHttpMsg();
        for (Rule testRule : getTestRules()) {
            Violation violation = new Violation(policyName, testRule, msg);
            assertEquals(msg.getRequestHeader().getURI().toString(), violation.getUri());
        }
    }
}
