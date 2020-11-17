package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

class StatementParserTest {

    // Input for Statement Parser
    private List<String> getTestStatements() {
        return new ArrayList<>(
                Arrays.asList(
                        "request.header.re=\"test\" or response.body.value=\"test2\" and ( request.header.values=[\"ada\",\"wfww\"] or not response.body.value=\"test4\")",
                        "request.header.re=\"test\" or response.body.value=\"test2\"",
                        "request.header.values=[\"ada\",\"wfww\"]",
                        "not not request.header.values=[\"ada\",\"wfww\"]"
                ));
    }


    // Expected Parse Result
    private List<String> getTestResults() {
        return new ArrayList<>(
                Arrays.asList(
                        "java.util.function.Predicate$$Lambda$31",
                        "java.util.function.Predicate$$Lambda$31",
                        "org.zaproxy.zap.extension.dslpolicyloader.checks.HttpPredicateBuilder",
                        "java.util.function.Predicate$$Lambda"
                ));
    }

    private List<HttpMessage> hardCodingTestTrue() throws URIException, HttpMalformedHeaderException {
        List<HttpMessage> msgs = new ArrayList<>();
        HttpMessage msg1 = new HttpMessage(new URI("http://example.com/", true));
        msg1.setCookieParamsAsString("[\"ada\",\"wfww\"]");
        msg1.setResponseBody("test2");

        HttpMessage msg3 = new HttpMessage(new URI("http://example.com/", true));
        msg3.setResponseBody("test2");

        HttpMessage msg4 = new HttpMessage(new URI("http://adawfww.com/", true));

        HttpMessage msg5 = new HttpMessage(new URI("http://adawfww.com/", true));

        msgs.add(msg1);
        msgs.add(msg3);
        msgs.add(msg4);
        msgs.add(msg5);

        return msgs;
    }

    private List<HttpMessage> hardCodingTestFalse() throws URIException, HttpMalformedHeaderException {
        List<HttpMessage> msgs = new ArrayList<>();
        HttpMessage msg1 = new HttpMessage(new URI("http://example.com/", true));

        HttpMessage msg3 = new HttpMessage(new URI("http://example.com/", true));
        msg3.setResponseBody("test3");

        HttpMessage msg4 = new HttpMessage(new URI("http://aawww.com/", true));

        HttpMessage msg5 = new HttpMessage(new URI("http://aafww.com/", true));

        msgs.add(msg1);
        msgs.add(msg3);
        msgs.add(msg4);
        msgs.add(msg5);

        return msgs;
    }

    @Test
    void parse() throws HttpMalformedHeaderException, URIException {
        List<String> tests = getTestStatements();
        List<String> results = getTestResults();

        List<HttpMessage> true_msgs = hardCodingTestTrue();
        List<HttpMessage> false_msgs = hardCodingTestFalse();

        Iterator<String> it_test = tests.iterator();
        Iterator<String> it_results = results.iterator();

        Iterator<HttpMessage> it_httpmsgT = true_msgs.iterator();
        Iterator<HttpMessage> it_httpmsgF = false_msgs.iterator();

        while(it_test.hasNext() && it_results.hasNext() && it_httpmsgT.hasNext() && it_httpmsgF.hasNext()){
            StatementParser sp_test = new StatementParser(it_test.next());
            Predicate<HttpMessage> predicate = sp_test.parse();

            assertTrue(predicate.toString().contains(it_results.next()));

            HttpMessage temp_httpT = it_httpmsgT.next();
            HttpMessage temp_httpF = it_httpmsgF.next();

            //System.out.println(predicate.toString());

            assertTrue(predicate.test(temp_httpT));
            assertFalse(predicate.test(temp_httpF));
        }
    }

    @Test
    void unitTest() throws HttpMalformedHeaderException, URIException {
        HttpMessage msg1 = new HttpMessage(new URI("http://adawfww.com/", true));
        msg1.setResponseBody("test2");

        StatementParser sp = new StatementParser("request.header.values=[\"ada\",\"wfww\"]");

        Predicate<HttpMessage> predicate = sp.parse();

        assertTrue(predicate.test(msg1));
    }
}