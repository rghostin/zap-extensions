package org.zaproxy.zap.extension.policyloader.rules;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HSTSRuleTest {

    HSTSRule hstsRule;

    @BeforeEach
    void setup() {
        hstsRule = new HSTSRule();
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    private List<String> getHSTSCorrect() {
        return new ArrayList<>(Arrays.asList(
                "max-age=1",
                "max-age=1;includeSubDomains",
                "max-age=123456",
                "max-age=123456 ; includeSubDomains",
                "max-age=123456;includeSubDomains;preload"
        ));
    }

    private List<String> getHSTSWrong() {
        return new ArrayList<>(Arrays.asList(
                "max_age=1;",
                "max-age=1a",
                "max-age=1;include",
                "max-age=1;includeSubDomains1",
                "max-age=123456;includeSubDomains;;preload"
        ));
    }

    @Test
    void getName() {
        assertEquals("HSTS_Rule",hstsRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals("The HTTP response message does not enforce HSTS.",hstsRule.getDescription());
    }

    @Test
    void isViolatedCorrect() throws HttpMalformedHeaderException, URIException {
        for (String val : getHSTSCorrect()) {
            HttpMessage msg = createHttpMsg();
            msg.getResponseHeader().setHeader("Strict-Transport-Security",val);
            assertFalse(hstsRule.isViolated(msg));
        }
    }

    @Test
    void isViolatedWrong() throws HttpMalformedHeaderException, URIException {
        for (String val : getHSTSWrong()) {
            HttpMessage msg = createHttpMsg();
            msg.getResponseHeader().setHeader("Strict-Transport-Security",val);
            assertTrue(hstsRule.isViolated(msg));
        }
    }
}