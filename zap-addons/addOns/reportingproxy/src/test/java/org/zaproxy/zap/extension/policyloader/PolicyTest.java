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
package org.zaproxy.zap.extension.policyloader;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.rules.*;

class PolicyTest {

    Policy testPolicy = new Policy("testPolicy");
    Set<Rule> rulesContainer = new HashSet<>();
    Map<String, String> violationsTitlesContainer = new HashMap<>();
    String COOKIE_NAME = "Cookie_Attribute_Rule";
    String DOMAIN_NAME = "Domain_matching_rule";
    String EMAIL_NAME = "Email_matching_rule";
    String EXCEPT_NAME = "ExpectCT_Rule";
    String HSTS_NAME = "HSTS_Rule";
    String HTTPS_NAME = "HTTPS";
    String KEYWORD_NAME = "Keyword_matching_rule";
    String COOKIE_TITLE = "Policy_testPolicy.Rule_Cookie_Attribute_Rule violated";
    String DOMAIN_TITLE = "Policy_testPolicy.Rule_Domain_matching_rule violated";
    String EMAIL_TITLE = "Policy_testPolicy.Rule_Email_matching_rule violated";
    String EXCEPT_TITLE = "Policy_testPolicy.Rule_ExpectCT_Rule violated";
    String HSTS_TITLE = "Policy_testPolicy.Rule_HSTS_Rule violated";
    String HTTPS_TITLE = "Policy_testPolicy.Rule_HTTPS violated";
    String KEYWORD_TITLE = "Policy_testPolicy.Rule_Keyword_matching_rule violated";

    Integer POLICY_SIZE = 1;

    @BeforeEach
    void setPolicy() {
        rulesContainer.clear();
        rulesContainer.add(new KeywordMatchingRule());
        rulesContainer.add(new HSTSRule());
        rulesContainer.add(new EmailMatchingRule());
        rulesContainer.add(new HTTPSRule());
        rulesContainer.add(new DomainMatchingRule());
        rulesContainer.add(new ExpectCTRule());
        rulesContainer.add(new CookieAttrRule());

        violationsTitlesContainer.clear();
        violationsTitlesContainer.put(COOKIE_NAME, COOKIE_TITLE);
        violationsTitlesContainer.put(DOMAIN_NAME, DOMAIN_TITLE);
        violationsTitlesContainer.put(EMAIL_NAME, EMAIL_TITLE);
        violationsTitlesContainer.put(EXCEPT_NAME, EXCEPT_TITLE);
        violationsTitlesContainer.put(HSTS_NAME, HSTS_TITLE);
        violationsTitlesContainer.put(HTTPS_NAME, HTTPS_TITLE);
        violationsTitlesContainer.put(KEYWORD_NAME, KEYWORD_TITLE);

        for (int i = 0; i < POLICY_SIZE; i++) {
            Rule rule = getRandomRule(rulesContainer);
            testPolicy.addRule(rule);
        }
    }

    @Test
    void getName() {
        assertEquals("testPolicy", testPolicy.getName());
    }

    @Test
    void addRule() {
        Rule rule = getRandomRule(rulesContainer);
        testPolicy.addRule(rule);
        Set<Rule> rules = testPolicy.getRules();
        assertTrue(contains(rules, rule));
    }

    @Test
    void removeRule() {
        Set<Rule> rules = testPolicy.getRules();
        Rule rule = getRandomRule(rules);
        testPolicy.removeRule(rule);
        System.out.println(rules);
        assertFalse(contains(rules, rule));
    }

    @Test
    void checkViolations() throws HttpMalformedHeaderException, URIException {
        List<String> targetViolationsTitles = new ArrayList<>();
        List<String> activatedRuleName = new ArrayList<>();
        Set<Rule> activatedRules = new HashSet<>();
        for (int i = 0; i < POLICY_SIZE; i++) {
            Rule rule = getRandomRule(testPolicy.getRules());
            if (!contains(activatedRules, rule)) {
                activatedRules.add(rule);
                targetViolationsTitles.add(violationsTitlesContainer.get(rule.getName()));
                activatedRuleName.add(rule.getName());
            }
        }

        HttpMessage httpMessage = createHttpMsg(activatedRuleName);
        List<Violation> checkViolations = testPolicy.checkViolations(httpMessage);
        assertTrue(equals(targetViolationsTitles, checkViolations));
    }

    private boolean contains(Set<Rule> rules, Rule newRule) {
        for (Rule rule : rules) {
            if (rule.getName().equals(newRule.getName())) {
                return true;
            }
        }
        return false;
    }

    private Rule getRandomRule(Set<Rule> rules) {
        int randomNum = new Random().nextInt(rules.size());
        int i = 0;
        for (Rule rule : rules) {
            if (i == randomNum) {
                return rule;
            }
            i++;
        }
        return null;
    }

    private boolean equals(List<String> targetViolationsTitles, List<Violation> checkViolations) {
        if (checkViolations == null) {
            return false;
        }
        if (checkViolations.size() == 0) {
            return false;
        }
        List<String> cVTitles = new ArrayList<>();
        for (Violation cV : checkViolations) {
            cVTitles.add(cV.getTitle());
        }
        return targetViolationsTitles.equals(cVTitles);
    }

    private HttpMessage createHttpMsg(List<String> ruleNames)
            throws URIException, HttpMalformedHeaderException {
        String url = "http://www.example.com/";
        String keyWord = "";
        String cookieAttribute = "HttpOnly; Secure; SameSite=None";
        String hSTSValue = "max-age=1";
        String expValue = "Expect-CT: max-age=%d\r\n\r\n";
        boolean https = true;

        // CookieAttrRule
        if (ruleNames.contains(COOKIE_NAME)) {
            cookieAttribute = "";
        }
        // DomainMatchingRule
        if (ruleNames.contains(DOMAIN_NAME)) {
            url = "www.zerohedge.com";
        }
        // HTTPSRule
        if (ruleNames.contains(HTTPS_NAME)) {
            url = "http://cern.ch/";
            https = false;
        }
        // ExceptCTRule
        if (ruleNames.contains(EXCEPT_NAME)) {
            url = "http://cern.ch/";
            expValue = "Expect-CT: \r\n\r\n";
        }
        HttpMessage msg = new HttpMessage(new URI(url, true));
        // EmailMatchingRule
        if (ruleNames.contains(EMAIL_NAME)) {
            msg.setRequestBody("lucas");
            msg.setResponseBody("@gmail.com");
        }
        // HSTSRule
        if (ruleNames.contains(HSTS_NAME)) {
            hSTSValue = "";
        }
        // KeywordMatchingRule
        if (ruleNames.contains(KEYWORD_NAME)) {
            keyWord = "hacker";
        }

        msg.getRequestHeader().setSecure(https);
        msg.setResponseHeader(
                String.format("HTTP/1.1 200 Connection established\r\n" + expValue, 1222));
        msg.setRequestBody(String.format("<html><head></head><body>%s</body><html>", keyWord));
        msg.setCookieParamsAsString(cookieAttribute);
        msg.getResponseHeader().setHeader("Strict-Transport-Security", hSTSValue);
        return msg;
    }
}
