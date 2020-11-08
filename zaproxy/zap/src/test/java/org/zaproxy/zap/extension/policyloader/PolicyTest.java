package org.zaproxy.zap.extension.policyloader;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.rules.*;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class PolicyTest {

    Policy testPolicy= new Policy("testPolicy");
    Set<Rule> rulesContainer = new HashSet<>();

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

        for (int i = 0; i < 3; i++) {
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
        List<Violation> checkViolations = testPolicy.checkViolations(createHttpMsg());
        assertTrue(equals(targetViolationsTitles, checkViolations));
    }

    private boolean contains(Set<Rule> rules, Rule newRule) {
        for (Rule rule: rules) {
            if (rule.getName().equals(newRule.getName())){
                return true;
            }
        }
        return false;
    }

    private Rule getRandomRule(Set<Rule> rules){
        int randomNum = new Random().nextInt(rules.size());
        int i = 0;
        for (Rule rule : rules) {
            if(i == randomNum){
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
            System.out.println(cV.getTitle());
            cVTitles.add(cV.getTitle());
        }

        return targetViolationsTitles.equals(cVTitles);
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        msg.setRequestBody(String.format("<html><head></head><body>%s</body><html>", "hacker"));
        return msg;
    }
}