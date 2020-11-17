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
        Predicate<HttpMessage> predicate;
        List<Token> tokens = tokenizers.get(0).getAllTokens();
        assertEquals(8, tokens.size());

        assertTrue(tokens.get(0).isSimplePredicate());
        predicate = (Predicate<HttpMessage>) tokens.get(0).getTokenObj();
        assertTrue(predicate.test(createHttpMsg("Request", "abc", "")));
        assertFalse(predicate.test(createHttpMsg("Request", "", "")));

        assertTrue(tokens.get(1).isOperator());
        if (tokens.get(1).isOperator()) {
            assertEquals(AndOperator.class,tokens.get(1).getTokenObj().getClass());
        }

        assertTrue(tokens.get(2).isOperator());
        if (tokens.get(2).isOperator()) {
            assertEquals(NotOperator.class, tokens.get(2).getTokenObj().getClass());
        }

        assertTrue(tokens.get(3).isOpenParenthesis());

        assertTrue(tokens.get(4).isSimplePredicate());
        predicate = (Predicate<HttpMessage>) tokens.get(4).getTokenObj();
        assertTrue(predicate.test(createHttpMsg("Response", "def", "")));
        assertFalse(predicate.test(createHttpMsg("Response", "", "")));

        assertTrue(tokens.get(5).isOperator());
        if (tokens.get(5).isOperator()) {
            assertEquals(OrOperator.class, tokens.get(5).getTokenObj().getClass());
        }

        assertTrue(tokens.get(6).isSimplePredicate());
        predicate = (Predicate<HttpMessage>) tokens.get(6).getTokenObj();
        assertTrue(predicate.test(createHttpMsg("Response", "", "x")));
        assertTrue(predicate.test(createHttpMsg("Response", "", "y")));
        assertTrue(predicate.test(createHttpMsg("Response", "", "xy")));
        assertFalse(predicate.test(createHttpMsg("Response", "", "")));

        assertTrue(tokens.get(7).isClosedParenthesis());
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
