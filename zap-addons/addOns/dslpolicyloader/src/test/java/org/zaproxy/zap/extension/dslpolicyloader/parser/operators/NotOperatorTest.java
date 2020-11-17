package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.checks.FieldType;
import org.zaproxy.zap.extension.dslpolicyloader.checks.HttpPredicateBuilder;
import org.zaproxy.zap.extension.dslpolicyloader.checks.TransmissionType;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class NotOperatorTest {

    AndOperator andOperator;
    NotOperator notOperator;
    OrOperator orOperator;
    List<Predicate<HttpMessage>> httpPredicates;
    Predicate<HttpMessage> httpPredicate;

    @BeforeEach
    void setup() {
        andOperator = new AndOperator();
        notOperator = new NotOperator();
        orOperator  = new OrOperator();
        HttpPredicateBuilder httpPredicateBuilder = new HttpPredicateBuilder();
        httpPredicates = new ArrayList<>();
        Pattern firstPattern = Pattern.compile("hacker", Pattern.CASE_INSENSITIVE);
        httpPredicate = httpPredicateBuilder.build(TransmissionType.REQUEST, FieldType.BODY, firstPattern);
        httpPredicates.add(httpPredicate);
    }

    @Test
    void hasHigherPrecedenceOver() {
        assertTrue(notOperator.hasHigherPrecedenceOver(andOperator));
        assertTrue(notOperator.hasHigherPrecedenceOver(orOperator));
    }

    @Test
    void getPrecedence() {
        assertEquals(3, notOperator.getPrecedence());
    }

    @Test
    void isLeftAssociative() {
        assertFalse(notOperator.isLeftAssociative());
    }

    @Test
    void operate() {
        Predicate<HttpMessage> predicate = notOperator.operate(httpPredicates);
        HttpMessage msg = createHttpMsg("hacker");
        assertTrue(httpPredicate.test(msg));
        assertFalse(predicate.test(msg));
    }

    private HttpMessage createHttpMsg(String keyword) {
        try {
            HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
            msg.setRequestBody(String.format("<html><head></head><body>%s</body><html>", keyword));
            return msg;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}