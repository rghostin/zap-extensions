package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.checks.*;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.*;

import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// todo test gen
@SuppressWarnings("unchecked")
public class StatementParser {
    private static final String RE_INSTRUCTION =
            "\\s*(request|response)\\.(header|body)\\.((?:re=\\\".*?\\\")|(?:value=\\\".*?\\\")|(?:values=\\[.*?\\]))\\s*";
    private static final Pattern PATTERN_INSTRUCTION = Pattern.compile(RE_INSTRUCTION);

    private static final String RE_LIAISON = "\\s*(and|or|not|\\(|\\))\\s*";
    private static final Pattern PATTERN_LIAISON = Pattern.compile(RE_LIAISON);

    private static final String RE_TOKEN = "("+ RE_INSTRUCTION +")|("+RE_LIAISON+")";
    private static final Pattern PATTERN_TOKEN = Pattern.compile(RE_TOKEN);

    private Matcher matcher;
    private String composedStatement;
    private int lastPos;

    public StatementParser(String composedStatement) {
        this.composedStatement = composedStatement;
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

    private Predicate<HttpMessage> parseSimplePredicate(Matcher matcherCheck) {
        String transmissionTypeStr = matcherCheck.group(1);
        String fieldOfOperationStr = matcherCheck.group(2);
        String matchingModeStr = matcherCheck.group(3);

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

    private enum TokenType{
        SIMPLE_PREDICATE,
        OPERATOR,
        PARENTHESIS
    }

    private class Token {
        TokenType tokenType;
        Object tokenObj;
        public Token(HttpPredicateOperator operator) {
            tokenType = TokenType.OPERATOR;
            tokenObj = operator;
        }

        public Token(Predicate<HttpMessage> msg) {
            tokenType = TokenType.SIMPLE_PREDICATE;
            tokenObj = msg;
        }

        public Object getTokenObj() {
            return tokenObj;
        }

        public boolean isSimplePredicate() {return tokenType == TokenType.SIMPLE_PREDICATE;}

        public boolean isOperator() {return tokenType == TokenType.OPERATOR;}
    }

    /**
     * Adapted Dijkstra's Shunting yard algorithm
     * Tranforms infix to postfix queue of tokens
     * @return postfix queue of tokens
     */
    private Queue<Token> shuntingYard() {
        Stack<Object> operatorStack = new Stack<>();
        Queue<Token> outputQueue = new LinkedList<>();

        String tokenStr;
        while ( (tokenStr = getNextTokenString()) != null ) {
            Matcher matcherLiaison = PATTERN_LIAISON.matcher(tokenStr);
            Matcher matcherInstruction = PATTERN_INSTRUCTION.matcher(tokenStr);

            if (matcherLiaison.matches()) {
                if (tokenStr.equals("(")) {
                    operatorStack.push("(");
                } else if ( tokenStr.equals(")")) {
                    while (! operatorStack.peek().equals("(")) {
                        HttpPredicateOperator op = (HttpPredicateOperator) operatorStack.pop();
                        outputQueue.add(new Token(op));
                    }
                } else {
                    // construct OpCheck
                    HttpPredicateOperator operator = parseOperator(tokenStr);

                    while (! operatorStack.empty()
                        && ! operatorStack.peek().equals("(")
                        && ((HttpPredicateOperator) operatorStack.peek()).hasHigherPrecedenceOver(operator)) {
                            HttpPredicateOperator op = (HttpPredicateOperator) operatorStack.pop();
                            outputQueue.add(new Token(op));
                    }
                    operatorStack.push(operator);
                }
            } else if (matcherInstruction.matches()) {
                // construct AtomicCheck
                Predicate<HttpMessage> httpPredicate = parseSimplePredicate(matcherInstruction);
                outputQueue.add(new Token(httpPredicate));
            } else {
                throw new IllegalStateException("Logic error");
            }
        }

        while (! operatorStack.empty()){
            HttpPredicateOperator op = (HttpPredicateOperator) operatorStack.pop();
            outputQueue.add(new Token(op));
        }
        return outputQueue;
    }

    private Predicate<HttpMessage> postfixEvaluator(Queue<Token> outputQueue) {
        Stack<Predicate<HttpMessage>> operandsStack = new Stack<>();

        for (Token t : outputQueue) {
            if (t.isSimplePredicate()) {
                operandsStack.push((Predicate<HttpMessage>) t.getTokenObj());
            } else if (t.isOperator()) {
                HttpPredicateOperator operator = (HttpPredicateOperator) t.getTokenObj();
                List<Predicate<HttpMessage>> operands = new ArrayList<>();
                for (int i = 0; i < operator.getArity(); i++) {
                    operands.add(operandsStack.pop());
                }
                Predicate<HttpMessage> predicate = operator.operate(operands);
                operandsStack.push(predicate);

            } else {
                throw new IllegalStateException("Maximum supported operator arity is 2");
            }
        }
        return operandsStack.pop();

    }




    public static void main(String[] args) { // todo remove
        String composedStatement = "request.header.re=\"test\" or response.body.value=\"test2\" and request.header.values=[\"ada\",\"wfww\"] or response.body.value=\"test4\"";

//        String token;
        StatementParser checkParser = new StatementParser(composedStatement);
//        while ( (token = tokenizer.getNextToken()) != null) {
//            System.out.println(token);
//        }

//        for (String token : new StatementParser(composedStatement)) {
//            System.out.println(token);
//        }

//        StatementParser tokenizer = new StatementParser(composedStatement);
//        Iterator<String> tokenIterator = tokenizer.iterator();
//        while (tokenIterator.hasNext()) {
//            System.out.println(tokenIterator.next());
//        }

//        List<Object> objects = checkParser.getTokens();
//        System.out.println(objects);

        Queue<Token> outputQ = checkParser.shuntingYard();
        Predicate<HttpMessage> pred = checkParser.postfixEvaluator(outputQ);
        System.out.println(pred);
        System.out.println(outputQ);
    }
}
