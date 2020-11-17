package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

import java.util.function.Predicate;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class HttpPredicateBuilderTest {

    HttpPredicateBuilder httpPredicateBuilder;

    @BeforeEach
    void setup() {
        httpPredicateBuilder = new HttpPredicateBuilder();
    }

    @Test
    void build() {
        Predicate<HttpMessage> predicate;
        Pattern pattern = Pattern.compile("abc", Pattern.CASE_INSENSITIVE);

        predicate = httpPredicateBuilder.build(TransmissionType.REQUEST, FieldType.BODY, pattern);
        assertTrue(predicate.test(createHttpMsg("Request", "", "abc")));

        predicate = httpPredicateBuilder.build(TransmissionType.RESPONSE, FieldType.BODY, pattern);
        assertTrue(predicate.test(createHttpMsg("Response", "", "abc")));

        predicate = httpPredicateBuilder.build(TransmissionType.REQUEST, FieldType.HEADER, pattern);
        assertTrue(predicate.test(createHttpMsg("Request", "abc", "")));

        predicate = httpPredicateBuilder.build(TransmissionType.RESPONSE, FieldType.HEADER, pattern);
        assertTrue(predicate.test(createHttpMsg("Response", "abc", "")));
    }

    private HttpMessage createHttpMsg(String transmission, String head, String body) {
        try {
            HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
            if ("Request".equals(transmission)) {
                if (!"".equals(head.trim())) {
                    // TODO:
                    msg.getRequestHeader().setHeader("abc", "abc");
                } else if (!"".equals(body.trim())) {
                    msg.setRequestBody(String.format("<html><head></head><body>%s</body><html>", body));
                }
            } else if ("Response".equals(transmission)) {
                if (!"".equals(head.trim())) {
                    // TODO:
                    msg.getResponseHeader().setHeader("abc", "abc");
                } else if (!"".equals(body.trim())) {
                    msg.setResponseBody(String.format("<html><head></head><body>%s</body><html>", body));
                }
            }
            return msg;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}