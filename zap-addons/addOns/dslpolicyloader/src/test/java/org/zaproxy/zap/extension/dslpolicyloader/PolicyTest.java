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

import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.exceptions.SyntaxErrorException;
import org.zaproxy.zap.extension.dslpolicyloader.parser.PolicyParser;
import org.zaproxy.zap.extension.dslpolicyloader.parser.StatementParser;

class PolicyTest {

    Policy testPolicy;
    PolicyParser policyParser;
    Rule testRule;
    private static final String RE_RULE_DECLARATION =
            "^Rule\\s+\"(.+?)\"\\s+\"(.+?)\"\\s*:\\s*(.+)$";
    private static final Pattern PATTERN_RULE_DECLARATION = Pattern.compile(RE_RULE_DECLARATION);

    @BeforeEach
    void setup() {
        policyParser = new PolicyParser();
        try {
            testPolicy = policyParser.parsePolicy(getPolicyContents().get(0), "testPolicy");
        } catch (SyntaxErrorException e) {
            e.printStackTrace();
        }

        try {
            testRule =
                    parseRule(
                            "Rule \"test_add_rule\" \"rule for addRule() and removeRule() test\":\n"
                                    + "response.body.value=\"test\";");
        } catch (SyntaxErrorException e) {
            e.printStackTrace();
        }
    }

    @Test
    void getName() {
        assertEquals("testPolicy", testPolicy.getName());
    }

    @Test
    void addRule() {
        testPolicy.addRule(testRule);
        assertTrue(contains(testPolicy.getRules(), testRule));
    }

    @Test
    void removeRule() {
        testPolicy.addRule(testRule);
        assertTrue(contains(testPolicy.getRules(), testRule));
        testPolicy.removeRule(testRule);
        assertFalse(contains(testPolicy.getRules(), testRule));
    }

    @Test
    void checkViolations() {
        List<String> targetActiveRuleNames = new ArrayList<>();
        HttpMessage httpMsg;

        targetActiveRuleNames.add("hacker_req_header_rule");
        httpMsg = createHttpMsg("Request", "hacker", "");
        assertTrue(equals(targetActiveRuleNames, testPolicy.checkViolations(httpMsg)));
        targetActiveRuleNames.clear();

        targetActiveRuleNames.add("hacker_req_body_rule");
        httpMsg = createHttpMsg("Request", "", "hacker");
        assertTrue(equals(targetActiveRuleNames, testPolicy.checkViolations(httpMsg)));
        targetActiveRuleNames.clear();

        targetActiveRuleNames.add("hacker_req_header_rule");
        targetActiveRuleNames.add("hacker_resp_header_rule");
        httpMsg = createHttpMsg("Request,Response", "hacker", "");
        assertTrue(equals(targetActiveRuleNames, testPolicy.checkViolations(httpMsg)));
        targetActiveRuleNames.clear();

        targetActiveRuleNames.add("hacker_req_header_rule");
        targetActiveRuleNames.add("hacker_req_body_rule");
        httpMsg = createHttpMsg("Request", "hacker", "hacker");
        assertTrue(equals(targetActiveRuleNames, testPolicy.checkViolations(httpMsg)));
        targetActiveRuleNames.clear();

        targetActiveRuleNames.add("hacker_resp_header_rule");
        targetActiveRuleNames.add("hacker_resp_body_rule");
        httpMsg = createHttpMsg("Response", "hacker", "hacker");
        assertTrue(equals(targetActiveRuleNames, testPolicy.checkViolations(httpMsg)));
        targetActiveRuleNames.clear();

        targetActiveRuleNames.add("hacker_resp_header_rule");
        targetActiveRuleNames.add("hacker_resp_body_rule");
        targetActiveRuleNames.add("hacker_req_header_rule");
        targetActiveRuleNames.add("hacker_req_body_rule");
        httpMsg = createHttpMsg("Response,Request", "hacker", "hacker");
        assertTrue(equals(targetActiveRuleNames, testPolicy.checkViolations(httpMsg)));
        targetActiveRuleNames.clear();
    }

    private List<String> getPolicyContents() {
        return new ArrayList<>(
                Arrays.asList(
                        "Rule \"hacker_req_header_rule\" \"hacker exists in the request header\":\n"
                                + "request.header.re=\"hacker\";\n"
                                + "Rule \"hacker_req_body_rule\" \"hacker exists in the request body\":\n"
                                + "request.body.value=\"hacker\";\n"
                                + "Rule \"hacker_resp_header_rule\" \"hacker exists in the response header\":\n"
                                + "response.header.value=\"hacker\";\n"
                                + "Rule \"hacker_resp_body_rule\" \"hacker exists in the response body\":\n"
                                + "response.body.value=\"hacker\";"));
    }

    private HttpMessage createHttpMsg(String transmission, String head, String body) {
        try {
            HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
            if (transmission.contains("Request")) {
                if (!"".equals(head.trim())) {
                    msg.getRequestHeader().setHeader(head, head);
                }
                if (!"".equals(body.trim())) {
                    msg.setRequestBody(
                            String.format("<html><head></head><body>%s</body><html>", body));
                }
            }
            if (transmission.contains("Response")) {
                if (!"".equals(head.trim())) {
                    msg.getResponseHeader().setHeader(head, head);
                }
                if (!"".equals(body.trim())) {
                    msg.setResponseBody(
                            String.format("<html><head></head><body>%s</body><html>", body));
                }
            }
            return msg;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private Rule parseRule(String ruleDsl) throws SyntaxErrorException {
        Matcher ruleMatcher = PATTERN_RULE_DECLARATION.matcher(ruleDsl);
        boolean matches = ruleMatcher.matches();
        assert matches;
        String name = ruleMatcher.group(1);
        String description = ruleMatcher.group(2);
        String composeodStatement = ruleMatcher.group(3);

        Predicate<HttpMessage> predicate = new StatementParser(composeodStatement).parse();
        return new Rule(name, description, predicate);
    }

    private boolean contains(Set<Rule> rules, Rule newRule) {
        for (Rule rule : rules) {
            if (rule.getName().equals(newRule.getName())) {
                return true;
            }
        }
        return false;
    }

    private boolean equals(List<String> targetActiveRuleNames, List<Violation> checkViolations) {
        if (checkViolations == null) {
            return false;
        }
        if (checkViolations.size() == 0) {
            return false;
        }
        List<String> cVRuleName = new ArrayList<>();
        for (Violation cV : checkViolations) {
            cVRuleName.add(cV.getRuleName());
        }
        String[] tarArr = targetActiveRuleNames.toArray(new String[] {});
        String[] cVArr = cVRuleName.toArray(new String[] {});
        Arrays.sort(tarArr);
        Arrays.sort(cVArr);
        return Arrays.equals(tarArr, cVArr);
    }
}
