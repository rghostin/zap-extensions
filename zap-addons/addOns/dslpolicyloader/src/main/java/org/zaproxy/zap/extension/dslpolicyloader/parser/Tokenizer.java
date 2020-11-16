package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.zaproxy.zap.extension.dslpolicyloader.checks.*;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tokenizer {
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

    public Tokenizer(String composedStatement) {
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

    private Operator parseOperator(String operator) {
        operator = operator.trim();
        Operator op = null;
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

    private Check parseCheck(Matcher matcherCheck) {
        String transmissionType = matcherCheck.group(1);
        String fieldOfOperation = matcherCheck.group(2);
        String matchingModeStr = matcherCheck.group(3);

        // TODO convert matchingModeStr to pattern
        Pattern pattern = Pattern.compile("");

        System.out.println(transmissionType + " " + fieldOfOperation + " " + matchingModeStr);
        Check check;
        if (transmissionType.equals("request") && fieldOfOperation.equals("header")) {
            check = new RequestHeaderCheck(pattern);
        } else if (transmissionType.equals("request") && fieldOfOperation.equals("body")) {
            check = new RequestBodyCheck(pattern);
        } else if (transmissionType.equals("response") && fieldOfOperation.equals("header")) {
            check = new ResponseHeaderCheck(pattern);
        } else if (transmissionType.equals("response") && fieldOfOperation.equals("body")) {
            check = new ResponseBodyCheck(pattern);
        } else {
            throw new IllegalStateException("Logic error");
        }
        return check;
    }

    public List<Object> getTokens() {
        List<Object> tokens = new ArrayList<>();

        String token;
        while ( (token = getNextTokenString()) != null ) {
            Matcher matcherLiaison = PATTERN_LIAISON.matcher(token);
            Matcher matcherInstruction = PATTERN_INSTRUCTION.matcher(token);

            if (matcherLiaison.matches()) {
                // construct OpCheck
                Operator operator = parseOperator(token);
                tokens.add(operator);
            } else if (matcherInstruction.matches()) {
                // construct AtomicCheck
                Check check = parseCheck(matcherInstruction);
                tokens.add(check);
            } else {
                throw new IllegalStateException("Logic error");
            }
        }

        return tokens;
    }




    public static void main(String[] args) { // todo remove
        String composedStatement = "request.header.re=\"test\" and response.body.value=\"test2\" or request.header.values=[\"ada\",\"wfww\"]";

//        String token;
        Tokenizer tokenizer = new Tokenizer(composedStatement);
//        while ( (token = tokenizer.getNextToken()) != null) {
//            System.out.println(token);
//        }

//        for (String token : new Tokenizer(composedStatement)) {
//            System.out.println(token);
//        }

//        Tokenizer tokenizer = new Tokenizer(composedStatement);
//        Iterator<String> tokenIterator = tokenizer.iterator();
//        while (tokenIterator.hasNext()) {
//            System.out.println(tokenIterator.next());
//        }

        List<Object> objects = tokenizer.getTokens();
        System.out.println(objects);
    }
}
