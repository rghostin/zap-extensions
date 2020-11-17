package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.parser.operators.HttpPredicateOperator;

import java.util.function.Predicate;

enum TokenType{
    SIMPLE_PREDICATE,
    OPERATOR,
    OPEN_PARENTHESIS,
    CLOSE_PARENTHESIS
}

public class Token {
    private TokenType tokenType;
    private Object tokenObj;
    public Token(HttpPredicateOperator operator) {
        tokenType = TokenType.OPERATOR;
        tokenObj = operator;
    }

    public Token(Predicate<HttpMessage> msg) {
        tokenType = TokenType.SIMPLE_PREDICATE;
        tokenObj = msg;
    }

    public Token(String s) {
        if (s.equals("(")) {
            tokenType = TokenType.OPEN_PARENTHESIS;
            tokenObj = "(";
        } else if (s.equals(")")) {
            tokenType = TokenType.CLOSE_PARENTHESIS;
            tokenObj = ")";
        } else {
            throw new IllegalArgumentException("Only ( and ) accepted");
        }
    }

    public Object getTokenObj() {
        return tokenObj;
    }

    public boolean isSimplePredicate() {return tokenType == TokenType.SIMPLE_PREDICATE;}

    public boolean isOperator() {return tokenType == TokenType.OPERATOR;}

    public boolean isOpenParenthesis() {return tokenType == TokenType.OPEN_PARENTHESIS;}

    public boolean isClosedParenthesis() {return tokenType == TokenType.CLOSE_PARENTHESIS;}
}