package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.checks.FieldType;
import org.zaproxy.zap.extension.dslpolicyloader.checks.HttpPredicateBuilder;
import org.zaproxy.zap.extension.dslpolicyloader.checks.TransmissionType;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.AndOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.HttpPredicateOperator;

import java.util.function.Predicate;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class TokenTest {

    Token operatorToken;
    Token predicateToken;
    Token openPartenthesisToken;
    Token closedPartenthesisToken;
    AndOperator operator;
    Predicate<HttpMessage> predicate;

    @BeforeEach
    void setup() {
        operator = new AndOperator();
        operatorToken = new Token(operator);
        predicate = new HttpPredicateBuilder().build(TransmissionType.REQUEST, FieldType.BODY, Pattern.compile("hacker", Pattern.CASE_INSENSITIVE));
        predicateToken = new Token(predicate);
        openPartenthesisToken = new Token("(");
        closedPartenthesisToken = new Token(")");
    }

    @Test
    void getTokenObj() {
        assertEquals(operator, operatorToken.getTokenObj());
        assertEquals(predicate, predicateToken.getTokenObj());
        assertEquals("(", openPartenthesisToken.getTokenObj());
        assertEquals(")", closedPartenthesisToken.getTokenObj());
    }

    @Test
    void isSimplePredicate() {
        assertFalse(operatorToken.isSimplePredicate());
        assertTrue(predicateToken.isSimplePredicate());
        assertFalse(openPartenthesisToken.isSimplePredicate());
        assertFalse(closedPartenthesisToken.isSimplePredicate());
    }

    @Test
    void isOperator() {
        assertTrue(operatorToken.isOperator());
        assertFalse(predicateToken.isOperator());
        assertFalse(openPartenthesisToken.isOperator());
        assertFalse(closedPartenthesisToken.isOperator());
    }

    @Test
    void isOpenParenthesis() {
        assertFalse(operatorToken.isOpenParenthesis());
        assertFalse(predicateToken.isOpenParenthesis());
        assertTrue(openPartenthesisToken.isOpenParenthesis());
        assertFalse(closedPartenthesisToken.isOpenParenthesis());
    }

    @Test
    void isClosedParenthesis() {
        assertFalse(operatorToken.isClosedParenthesis());
        assertFalse(predicateToken.isClosedParenthesis());
        assertFalse(openPartenthesisToken.isClosedParenthesis());
        assertTrue(closedPartenthesisToken.isClosedParenthesis());
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