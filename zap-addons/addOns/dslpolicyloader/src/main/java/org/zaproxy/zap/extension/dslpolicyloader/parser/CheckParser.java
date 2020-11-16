package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.checks.*;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.*;

import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// todo test gen
public class CheckParser {
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

    public CheckParser(String composedStatement) {
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

    private Predicate<HttpMessage> parseCheck(Matcher matcherCheck) {
        String transmissionTypeStr = matcherCheck.group(1);
        String fieldOfOperationStr = matcherCheck.group(2);
        String matchingModeStr = matcherCheck.group(3);

        // TODO convert matchingModeStr to pattern
        Pattern pattern = Pattern.compile("");
        TransmissionType transmissionType;
        FieldOfOperation fieldOfOperation;

        if (transmissionTypeStr.equals("request")) {
            transmissionType = TransmissionType.REQUEST;
        } else if (transmissionTypeStr.equals("response")) {
            transmissionType = TransmissionType.RESPONSE;
        }  else {
            throw new IllegalStateException("Logic error");
        }

        if (fieldOfOperationStr.equals("header")) {
            fieldOfOperation = FieldOfOperation.HEADER;
        } else if (fieldOfOperationStr.equals("body")) {
            fieldOfOperation = FieldOfOperation.BODY;
        } else {
            throw new IllegalStateException("Logic error");
        }
        return new HttpPredicateBuilder(transmissionType, fieldOfOperation, pattern).build();
    }

    public List<Object> getTokens() {
        List<Object> tokens = new ArrayList<>();

        String token;
        while ( (token = getNextTokenString()) != null ) {
            Matcher matcherLiaison = PATTERN_LIAISON.matcher(token);
            Matcher matcherInstruction = PATTERN_INSTRUCTION.matcher(token);

            if (matcherLiaison.matches()) {
                if (token.equals("(") || token.equals(")")) {
                    tokens.add(token);
                } else {
                    // construct OpCheck
                    HttpPredicateOperator operator = parseOperator(token);
                    tokens.add(operator);
                }
            } else if (matcherInstruction.matches()) {
                // construct AtomicCheck
                Predicate<HttpMessage> httpPredicate = parseCheck(matcherInstruction);
                tokens.add(httpPredicate);
            } else {
                throw new IllegalStateException("Logic error");
            }
        }
        return tokens;
    }


    /**
     * Adapted Dijkstra's Shunting yard algorithm
     * Tranforms infix to postfix queue of tokens
     * @return postfix queue of tokens
     */
    private Queue<Object> shuntingYard() {
        Stack<Object> operatorStack = new Stack<>();
        Queue<Object> outputQueue = new ArrayDeque<>();

        String token;
        while ( (token = getNextTokenString()) != null ) {
            Matcher matcherLiaison = PATTERN_LIAISON.matcher(token);
            Matcher matcherInstruction = PATTERN_INSTRUCTION.matcher(token);

            if (matcherLiaison.matches()) {
                if (token.equals("(")) {
                    operatorStack.push("(");
                } else if ( token.equals(")")) {
                    while (! operatorStack.peek().equals("(")) {
                        outputQueue.add(operatorStack.pop());
                    }
                } else {
                    // construct OpCheck
                    HttpPredicateOperator operator = parseOperator(token);

                    while (! operatorStack.empty()
                        && ! operatorStack.peek().equals("(")
                        && ((HttpPredicateOperator) operatorStack.peek()).hasHigherPrecedenceOver(operator)) {
                        outputQueue.add(operatorStack.pop());
                    }
                    operatorStack.push(operator);
                }
            } else if (matcherInstruction.matches()) {
                // construct AtomicCheck
                Predicate<HttpMessage> httpPredicate = parseCheck(matcherInstruction);
                outputQueue.add(httpPredicate);
            } else {
                throw new IllegalStateException("Logic error");
            }
        }

        while (! operatorStack.empty()){
            outputQueue.add(operatorStack.pop());
        }
        return outputQueue;
    }

    private Predicate<HttpMessage> postfixEvaluator(Queue<Object> outputQueue) {
        Stack<Predicate<HttpMessage>> operandsStack = new Stack<>();

        for (Object o : outputQueue.toArray()) {
            if (o instanceof Predicate<HttpMessage>) {
                operandsStack.push((Predicate<HttpMessage>) o);
            } else if (o instanceof HttpPredicateOperator) {
                HttpPredicateOperator operator = (HttpPredicateOperator) o;
                List<HttpPredicate> operands = new ArrayList<>();
                for (int i = 0; i < operator.getArity(); i++) {
                    operands.add(operandsStack.pop());
                }
                HttpPredicate predicate = operator.operate(operands);
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
        CheckParser checkParser = new CheckParser(composedStatement);
//        while ( (token = tokenizer.getNextToken()) != null) {
//            System.out.println(token);
//        }

//        for (String token : new CheckParser(composedStatement)) {
//            System.out.println(token);
//        }

//        CheckParser tokenizer = new CheckParser(composedStatement);
//        Iterator<String> tokenIterator = tokenizer.iterator();
//        while (tokenIterator.hasNext()) {
//            System.out.println(tokenIterator.next());
//        }

//        List<Object> objects = checkParser.getTokens();
//        System.out.println(objects);

        Queue<Object> outputQ = checkParser.shuntingYard();
        HttpPredicate pred = checkParser.postfixEvaluator(outputQ);
        System.out.println(pred);
        System.out.println(outputQ);
    }
}
