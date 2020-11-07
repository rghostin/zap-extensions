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

class DomainMatchingRuleTest {

    DomainMatchingRule domainRule;

    @BeforeEach
    void setup() {
        domainRule = new DomainMatchingRule();
    }

    private HttpMessage createHttpMsg(String url) throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI(url, true));
        return msg;
    }

    private List<String> getURLStringsCorrect() {
        return new ArrayList<>(Arrays.asList(
                "www.google.com",
                "www.zerohege.com",
                "www.youtube.com",
                "www.imd.com",
                "http://www.cer.ch"
        ));
    }

    private List<String> getURLStringsWrong() {
        return new ArrayList<>(Arrays.asList(
                "www.zerohedge.com",
                "http://www.imdb.com",
                "www.cern.ch",
                "www.zerohedge.com",
                "www.imdb.com",
                "www.cern.ch"
        ));
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
        for(String url : getURLStringsCorrect()){
            HttpMessage msg = createHttpMsg(url);
            assertFalse(domainRule.isViolated(msg));
        }
    }

    @Test
    void isViolatedTrue() throws HttpMalformedHeaderException, URIException {
        for(String url : getURLStringsWrong()){
            HttpMessage msg = createHttpMsg(url);
            assertTrue(domainRule.isViolated(msg));
        }
    }

}