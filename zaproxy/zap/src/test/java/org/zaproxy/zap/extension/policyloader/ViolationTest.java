package org.zaproxy.zap.extension.policyloader;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ViolationTest {

    class TestRule implements Rule {

        @Override
        public String getName() {
            return "Test Rule Name";
        }

        @Override
        public String getDescription() {
            return "Test Rule Description";
        }

        @Override
        public boolean isViolated(HttpMessage msg) {
            return false;
        }
    }

    private List<TestRule> getTestRules() {
        TestRule testRule = new TestRule();
        return new ArrayList<TestRule>(
                Arrays.asList(testRule));
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    @Test
    void getPolicyName() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test";
        HttpMessage msg = createHttpMsg();
        for(TestRule testRule : getTestRules()) {
            Violation violation = new Violation(policyName,testRule,msg);
            assertEquals(policyName,violation.getPolicyName());
        }
    }

    @Test
    void getRuleName() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test";
        HttpMessage msg = createHttpMsg();
        for(TestRule testRule : getTestRules()) {
            Violation violation = new Violation(policyName,testRule,msg);
            assertEquals(testRule.getName(),violation.getRuleName());
        }
    }

    @Test
    void getDescription() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test";
        HttpMessage msg = createHttpMsg();
        for(TestRule testRule : getTestRules()) {
            Violation violation = new Violation(policyName,testRule,msg);
            assertEquals(testRule.getDescription(),violation.getDescription());
        }
    }

    @Test
    void getMsg() throws HttpMalformedHeaderException, URIException {
        String policyName = "Test";
        HttpMessage msg = createHttpMsg();
        for(TestRule testRule : getTestRules()) {
            Violation violation = new Violation(policyName,testRule,msg);
            assertEquals(msg,violation.getMsg());
        }
    }
}