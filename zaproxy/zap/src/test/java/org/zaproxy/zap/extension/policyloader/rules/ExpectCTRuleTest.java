package org.zaproxy.zap.extension.policyloader.rules;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static org.junit.jupiter.api.Assertions.*;

class ExpectCTRuleTest {

    ExpectCTRule expectRule ;
    String EXP_HEADER = "Expect-CT: max-age=%d\r\n\r\n";
    String NON_EXP_HEADER = "Expect-CT: \r\n\r\n";

    @BeforeEach
    void setup() {
        expectRule = new ExpectCTRule();
    }

    @Test
    void getName() {
        assertEquals("ExpectCT_Rule", expectRule.getName());
    }

    @Test
    void getDescription() { assertEquals("The HTTP response message does not enforce ExpectCT Rule.", expectRule.getDescription()); }

    private HttpMessage createHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI(String.format("http://%s/", expectRule.getMyAppName()),
                true));
        return msg;
    }

    private HttpMessage createNonMyAppHttpMsg() throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
        return msg;
    }

    //The case in which there is Expect-CT and the domain is myAPP
    @Test
    void isMyAppViolatedWithExp() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createHttpMsg();
        msg.setResponseHeader(String.format("HTTP/1.1 200 Connection established\r\n" + EXP_HEADER,1222));
        assertFalse(expectRule.isViolated(msg));
    }

    //The case in which there isn't Expect-CT and the domain is myAPP
    @Test
    void isMyAppViolatedWithoutExp() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createHttpMsg();
        msg.setResponseHeader(String.format("HTTP/1.1 200 Connection established\r\n" + NON_EXP_HEADER,1222));
        assertTrue(expectRule.isViolated(msg));
    }

    //The case in which there is Expect-CT and the domain  is not myAPP
    @Test
    void isNotMyAppViolatedWithExp() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createNonMyAppHttpMsg();
        msg.setResponseHeader(String.format("HTTP/1.1 200 Connection established\r\n" + EXP_HEADER,1222));
        assertFalse(expectRule.isViolated(msg));
    }

    //The case in which there isn't Expect-CT and the domain is myAPP
    @Test
    void isNotMyAppViolatedWithoutExp() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg = createNonMyAppHttpMsg();
        msg.setResponseHeader(String.format("HTTP/1.1 200 Connection established\r\n" + NON_EXP_HEADER,1222));
        assertFalse(expectRule.isViolated(msg));
    }
}