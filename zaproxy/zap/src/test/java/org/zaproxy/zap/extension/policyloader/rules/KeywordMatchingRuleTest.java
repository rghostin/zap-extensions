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

// todo test
class KeywordMatchingRuleTest {
    KeywordMatchingRule kwordRule ;
    String BODY = "<html><head></head><body>%s</body><html>";

    @BeforeEach
    void setup() {
        kwordRule = new KeywordMatchingRule();
    }

    @Test
    void getName() {
        assertEquals("Keyword_matching_rule", kwordRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals("The HTTP message contains a flagged keyword.", kwordRule.getDescription());
    }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    private List<String> getPreGeneratedRandomString() {
        return new ArrayList<>(Arrays.asList(
                "HdLw7thzug1qeEi",
                "IkyF0U60BCQwulo",
                "IDluIxJUEVh92XV",
                "qey1Uehu2kuN9zL",
                "oauuKUGcphrf2g9",
                "fMWhQVd7ZguOLLp",
                "hTn6mdE47Jl2mn9",
                "Of9CsK2GYpM3DD7",
                "3lLerf2oIVWdQGy",
                "5CQftcNPn1ID9Wb"
        ));

    }

    @Test
    void isViolated() throws HttpMalformedHeaderException, URIException {

        for (String kword : kwordRule.getFlaggedKeywords()) {
            HttpMessage msg = createHttpMsg();
            msg.setRequestBody(String.format(BODY, kword));
            assertTrue(kwordRule.isViolated(msg));
        }

        for (String kword : getPreGeneratedRandomString()) {
            HttpMessage msg = createHttpMsg();
            msg.setRequestBody(String.format(BODY, kword));
            assertFalse(kwordRule.isViolated(msg));
        }

    }
}