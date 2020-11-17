package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.checks.HttpPredicateBuilder;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.AndOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.HttpPredicateOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.NotOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.OrOperator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

class TokenizerTest {

    List<Tokenizer> tokenizers;

    @BeforeEach
    void setup() {
        tokenizers = new ArrayList<>();
        List<String> composedStatements = getComposedStatements();
        for (String statement : composedStatements) {
            tokenizers.add(new Tokenizer(statement));
        }
    }

    private List<String> getComposedStatements() {
        return new ArrayList<>(
                Arrays.asList(
                        "request.header.re=\"abc\" and not ( response.header.value=\"def\" or response.body.values=[\"x\",\"y\",\"z\"] ) "
                )
        );
    }

    @Test
    void getAllTokens() {
        Predicate predicate;
        List<Token> tokens = tokenizers.get(0).getAllTokens();
        assertEquals(8, tokens.size());

        assertEquals(TokenType.SIMPLE_PREDICATE, tokens.get(0).tokenType);
        predicate = (Predicate) tokens.get(0).tokenObj;
        // TODO: test for pattern
        // assertTrue(predicate.test(createHttpMsg("abc", "")));
        // assertFalse(predicate.test(createHttpMsg("", "")));

        assertEquals(TokenType.OPERATOR, tokens.get(1).tokenType);
        assertEquals(AndOperator.class,tokens.get(1).getTokenObj().getClass());

        assertEquals(TokenType.OPERATOR, tokens.get(2).tokenType);
        assertEquals(NotOperator.class, tokens.get(2).tokenObj.getClass());

        assertEquals(TokenType.OPEN_PARENTHESIS, tokens.get(3).tokenType);
        assertEquals("(", tokens.get(3).getTokenObj());

        assertEquals(TokenType.SIMPLE_PREDICATE, tokens.get(4).tokenType);
        predicate = (Predicate) tokens.get(4).tokenObj;
        // TODO: test for pattern
        // assertTrue(predicate.test(createHttpMsg("def", "")));
        // assertFalse(predicate.test(createHttpMsg("", "")));

        assertEquals(TokenType.OPERATOR, tokens.get(5).tokenType);
        assertEquals(OrOperator.class, tokens.get(5).getTokenObj().getClass());

        assertEquals(TokenType.SIMPLE_PREDICATE, tokens.get(6).tokenType);
        predicate = (Predicate) tokens.get(6).tokenObj;
        // TODO: test for pattern
        // assertTrue(predicate.test(createHttpMsg("", "x")));
        // assertTrue(predicate.test(createHttpMsg("", "yz")));
        // assertFalse(predicate.test(createHttpMsg("", "")));

        assertEquals(TokenType.CLOSE_PARENTHESIS, tokens.get(7).tokenType);
        assertEquals(")", tokens.get(7).getTokenObj());

    }

    private HttpMessage createHttpMsg(String head, String body) {
        try {
            HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));

            msg.setRequestBody(String.format("<html><head>%s</head><body>%s</body><html>", head, body));
            return msg;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}