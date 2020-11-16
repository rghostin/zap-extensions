package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.checks.FieldType;
import org.zaproxy.zap.extension.dslpolicyloader.checks.HttpPredicateBuilder;
import org.zaproxy.zap.extension.dslpolicyloader.checks.TransmissionType;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.AndOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.HttpPredicateOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.NotOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.OrOperator;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tokenizer {
    private static final String RE_SIMPLE_PREDICATE =
            "\\s*(request|response)\\.(header|body)\\.((?:re=\\\".*?\\\")|(?:value=\\\".*?\\\")|(?:values=\\[.*?\\]))\\s*";
    private static final Pattern PATTERN_SIMPLE_PREDICATE = Pattern.compile(RE_SIMPLE_PREDICATE);

    private static final String RE_OPERATOR = "\\s*(and|or|not)\\s*";
    private static final Pattern PATTERN_OPERATOR = Pattern.compile(RE_OPERATOR);

    private static final String RE_PARENTHESIS = "\\s*\\(|\\)\\s*";

    private static final String RE_TOKEN = "("+ RE_SIMPLE_PREDICATE +")|("+RE_OPERATOR+")|("+RE_PARENTHESIS+")";
    private static final Pattern PATTERN_TOKEN = Pattern.compile(RE_TOKEN);

    private final Matcher matcher;
    private int lastPos;

    public Tokenizer(String composedStatement) {
        this.lastPos = 0;
        this.matcher = PATTERN_TOKEN.matcher(composedStatement);
    }

    private String getNextTokenString() {
        if (matcher.find(lastPos)) {
            lastPos = matcher.end();
            return matcher.group().trim();
        } else {
            return null;
        }
    }

    public List<Token> getAllTokens() {
        List<Token> tokens = new ArrayList<>();

        Matcher m;
        String tokenStr;
        while ( (tokenStr = getNextTokenString()) != null ) {
            if (tokenStr.equals("(")) {
                tokens.add(new Token("("));
            } else if ( tokenStr.equals(")")) {
                tokens.add(new Token(")"));
            } else if (PATTERN_OPERATOR.matcher(tokenStr).matches()) {
                HttpPredicateOperator operator = parseOperator(tokenStr);
                tokens.add(new Token(operator));
            } else if ( (m= PATTERN_SIMPLE_PREDICATE.matcher(tokenStr)).matches()) {
                Predicate<HttpMessage> httpPredicate = parseSimplePredicate(m);
                tokens.add(new Token(httpPredicate));
            } else {
                throw new IllegalStateException("Logic error");
            }
        }
        return tokens;
    }

    private HttpPredicateOperator parseOperator(String operator) {
        operator = operator.trim();
        HttpPredicateOperator op = null;
        switch (operator) {
            case "and":
                op = new AndOperator();
                break;
            case "or":
                op = new OrOperator();
                break;
            case "not":
                op = new NotOperator();
                break;
            default:
                throw new IllegalArgumentException("Unknown operator "+operator);
        }
        return op;
    }

    private Predicate<HttpMessage> parseSimplePredicate(Matcher matcherSimplePred) {
        String transmissionTypeStr = matcherSimplePred.group(1);
        String fieldOfOperationStr = matcherSimplePred.group(2);
        String matchingModeStr = matcherSimplePred.group(3);

        // TODO convert matchingModeStr to pattern
        Pattern pattern = Pattern.compile("");
        TransmissionType transmissionType;
        FieldType fieldType;

        if (transmissionTypeStr.equals("request")) {
            transmissionType = TransmissionType.REQUEST;
        } else if (transmissionTypeStr.equals("response")) {
            transmissionType = TransmissionType.RESPONSE;
        }  else {
            throw new IllegalStateException("Logic error");
        }

        if (fieldOfOperationStr.equals("header")) {
            fieldType = FieldType.HEADER;
        } else if (fieldOfOperationStr.equals("body")) {
            fieldType = FieldType.BODY;
        } else {
            throw new IllegalStateException("Logic error");
        }
        return new HttpPredicateBuilder().build(transmissionType, fieldType, pattern);
    }
}
