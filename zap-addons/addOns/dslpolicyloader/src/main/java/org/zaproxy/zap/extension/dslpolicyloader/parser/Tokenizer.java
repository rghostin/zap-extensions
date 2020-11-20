/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.dslpolicyloader.parser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.exceptions.SyntaxErrorException;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.AndOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.HttpPredicateOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.NotOperator;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.OrOperator;
import org.zaproxy.zap.extension.dslpolicyloader.predicate.FieldType;
import org.zaproxy.zap.extension.dslpolicyloader.predicate.HttpPredicateBuilder;
import org.zaproxy.zap.extension.dslpolicyloader.predicate.TransmissionType;

public class Tokenizer {
    private static final String RE_SIMPLE_PREDICATE =
            "\\s*(request|response)\\.(header|body)\\.((?:re=\\\".*?\\\")|(?:value=\\\".*?\\\")|(?:values=\\[.*?\\]))\\s*";
    private static final Pattern PATTERN_SIMPLE_PREDICATE = Pattern.compile(RE_SIMPLE_PREDICATE);

    private static final String RE_OPERATOR = "\\s*(and|or|not)\\s*";
    private static final Pattern PATTERN_OPERATOR = Pattern.compile(RE_OPERATOR);

    private static final String RE_PARENTHESIS = "\\s*\\(|\\)\\s*";

    private static final String RE_TOKEN =
            "(" + RE_SIMPLE_PREDICATE + ")|(" + RE_OPERATOR + ")|(" + RE_PARENTHESIS + ")";
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

    public List<Token> getAllTokens() throws SyntaxErrorException {
        List<Token> tokens = new ArrayList<>();

        Matcher m;
        String tokenStr;
        while ((tokenStr = getNextTokenString()) != null) {
            if (tokenStr.equals("(")) {
                tokens.add(new Token("("));
            } else if (tokenStr.equals(")")) {
                tokens.add(new Token(")"));
            } else if (PATTERN_OPERATOR.matcher(tokenStr).matches()) {
                HttpPredicateOperator operator = parseOperator(tokenStr);
                tokens.add(new Token(operator));
            } else if ((m = PATTERN_SIMPLE_PREDICATE.matcher(tokenStr)).matches()) {
                Predicate<HttpMessage> httpPredicate = parseSimplePredicate(m);
                tokens.add(new Token(httpPredicate));
            } else {
                throw new SyntaxErrorException("Unexpected token string: " + tokenStr);
            }
        }
        return tokens;
    }

    private HttpPredicateOperator parseOperator(String operator) throws SyntaxErrorException {
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
                throw new SyntaxErrorException("Unknown operator: " + operator);
        }
        return op;
    }

    private Pattern parseMatchingModeString(String matchingModeStr) throws SyntaxErrorException {
        String matchingMode = matchingModeStr.substring(0, matchingModeStr.indexOf("="));
        String arg =
                matchingModeStr.substring(
                        matchingModeStr.indexOf("=") + 2, // skip ="
                        matchingModeStr.length() - 1 // skip last "
                        );

        Pattern pattern;
        switch (matchingMode) {
            case "re":
                pattern = Pattern.compile(arg);
                break;
            case "value":
                pattern = ValueToPatternAdapter.getPatternFromValue(arg);
                break;
            case "values":
                List<String> values = new ArrayList<>();
                for (String value : Arrays.asList(arg.split(","))) {
                    values.add(
                            value.substring(1, value.length() - 1) // remove the " "
                            );
                }
                pattern = ValueToPatternAdapter.getPatternsFromValues(values);
                break;
            default:
                throw new SyntaxErrorException("Unknown matching mode: " + matchingMode);
        }
        return pattern;
    }

    private Predicate<HttpMessage> parseSimplePredicate(Matcher matcherSimplePred)
            throws SyntaxErrorException {
        String transmissionTypeStr = matcherSimplePred.group(1);
        String fieldTypeStr = matcherSimplePred.group(2);
        String matchingModeStr = matcherSimplePred.group(3);

        Pattern pattern = parseMatchingModeString(matchingModeStr);
        TransmissionType transmissionType;
        FieldType fieldType;

        if (transmissionTypeStr.equals("request")) {
            transmissionType = TransmissionType.REQUEST;
        } else if (transmissionTypeStr.equals("response")) {
            transmissionType = TransmissionType.RESPONSE;
        } else {
            throw new SyntaxErrorException("Unknown transmission type: " + transmissionTypeStr);
        }

        if (fieldTypeStr.equals("header")) {
            fieldType = FieldType.HEADER;
        } else if (fieldTypeStr.equals("body")) {
            fieldType = FieldType.BODY;
        } else {
            throw new SyntaxErrorException("Unknown field type: " + fieldTypeStr);
        }
        return new HttpPredicateBuilder().build(transmissionType, fieldType, pattern);
    }
}
