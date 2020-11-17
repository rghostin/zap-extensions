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

class OrOperatorTest {

    AndOperator andOperator;
    NotOperator notOperator;
    OrOperator orOperator;
    List<Predicate<HttpMessage>> httpPredicates;

    @BeforeEach
    void setup() {
        andOperator = new AndOperator();
        notOperator = new NotOperator();
        orOperator  = new OrOperator();
        HttpPredicateBuilder httpPredicateBuilder = new HttpPredicateBuilder();
        httpPredicates = new ArrayList<>();
        Pattern firstPattern = Pattern.compile("hacker", Pattern.CASE_INSENSITIVE);
        Pattern secondPattern = Pattern.compile("123", Pattern.CASE_INSENSITIVE);
        httpPredicates.add(httpPredicateBuilder.build(TransmissionType.REQUEST, FieldType.BODY, firstPattern));
        httpPredicates.add(httpPredicateBuilder.build(TransmissionType.REQUEST, FieldType.BODY, secondPattern));
    }

    @Test
    void hasHigherPrecedenceOver() {
        assertFalse(orOperator.hasHigherPrecedenceOver(andOperator));
        assertFalse(orOperator.hasHigherPrecedenceOver(notOperator));
    }

    @Test
    void getArity() {
        assertEquals(2, orOperator.getArity());
    }

    @Test
    void isLeftAssociative() {
        assertTrue(orOperator.isLeftAssociative());
    }

    @Test
    void operate() {
        Predicate<HttpMessage> predicate = orOperator.operate(httpPredicates);
        assertTrue(predicate.test(createHttpMsg("hacker123")));
        assertTrue(predicate.test(createHttpMsg("hacker")));
        assertTrue(predicate.test(createHttpMsg("123")));
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