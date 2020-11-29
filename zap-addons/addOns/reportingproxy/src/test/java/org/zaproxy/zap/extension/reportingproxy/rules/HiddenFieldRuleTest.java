package org.zaproxy.zap.extension.reportingproxy.rules;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Pair;
import org.zaproxy.zap.extension.reportingproxy.Violation;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;


class HiddenFieldRuleTest {

    private List<String> getURLStringsCorrect() {
        return new ArrayList<>(
                Arrays.asList(
                        "www.google.com",
                        "www.zerohege.com",
                        "www.youtube.com",
                        "www.imd.com",
                        "http://www.cer.ch"));
    }

    private List<String> getURLStringsWrong() {
        return new ArrayList<>(
                Arrays.asList(
                        "www.google2.com",
                        "www.zerohege2.com",
                        "www.youtube2.com",
                        "www.imd2.com",
                        "www.cern.ch"));
    }

    private HttpMessage createHttpMsg(String url) throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI(url, true));
        return msg;
    }

    @Test
    void getName() {
        HiddenFieldRule hiddenFieldRule = new HiddenFieldRule();
        assertEquals("Hidden Field Rule", hiddenFieldRule.getName());
    }

    @Test
    void getDescription() {
        HiddenFieldRule hiddenFieldRule = new HiddenFieldRule();
        assertEquals("Check if Hidden Field ever sent to different domain",hiddenFieldRule.getDescription());
    }

    @Test
    void checkViolation() throws HttpMalformedHeaderException, URIException {
        String responseBody = "<input type=\"hidden\" name=\"test\" value=\"babble\">";
        String responseBody2 = "<input type=\"hidden\" id=\"123\" name=\"tes2t\" value=\"babble\">";

        List<String> url_correct = getURLStringsCorrect();
        List<String> url_correct2 = getURLStringsCorrect();
        List<String> url_wrong = getURLStringsWrong();

        Iterator<String> uc = url_correct.iterator();
        Iterator<String> uc2 = url_correct2.iterator();
        Iterator<String> uw = url_wrong.iterator();

        while(uc.hasNext() && uc2.hasNext() && uw.hasNext()) {
            // each time get a empty rule to check
            HiddenFieldRule hiddenFieldRule = new HiddenFieldRule();

            HttpMessage httpMessageCorrect = createHttpMsg(uc.next());
            httpMessageCorrect.setResponseBody(responseBody);

            HttpMessage httpMessageCorrect2 = createHttpMsg(uc2.next());
            httpMessageCorrect2.setResponseBody(responseBody2);

            HttpMessage httpMessageWrong = createHttpMsg(uw.next());
            httpMessageWrong.setResponseBody(responseBody);

            // serial assertion
            assertNull(hiddenFieldRule.checkViolation(httpMessageCorrect));
            assertNull(hiddenFieldRule.checkViolation(httpMessageCorrect2));

            Violation v = hiddenFieldRule.checkViolation(httpMessageWrong);
            assertEquals(hiddenFieldRule.getName(),v.getRuleName());
            assertEquals(hiddenFieldRule.getDescription(),v.getDescription());
            assertEquals(httpMessageWrong.getRequestHeader().getURI().toString(),v.getUri());
        }
    }
}