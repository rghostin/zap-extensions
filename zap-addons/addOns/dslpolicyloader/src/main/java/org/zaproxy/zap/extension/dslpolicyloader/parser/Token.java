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

/**
 * Represents a token in the Domain Specific language
 * Token objects are used for parsing purposes
 */
public class Token {
    TokenType tokenType;
    Object tokenObj;

    /**
     * Construct token representing a DSL operator
     * @param operator : the DSL operator
     */
    public Token(HttpPredicateOperator operator) {
        tokenType = TokenType.OPERATOR;
        tokenObj = operator;
    }

    /**
     * Construct token representing a simple predicate
     * @param predicate : the Predicate
     */
    public Token(Predicate<HttpMessage> predicate) {
        tokenType = TokenType.SIMPLE_PREDICATE;
        tokenObj = predicate;
    }

    /**
     * Construct a token representing a parenthesis in the DSL
     * @param s: the parenthesis
     */
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

    /**
     * @return the object represented by this token
     */
    public Object getTokenObj() {
        return tokenObj;
    }

    public boolean isSimplePredicate() {return tokenType == TokenType.SIMPLE_PREDICATE;}

    public boolean isOperator() {return tokenType == TokenType.OPERATOR;}

    public boolean isOpenParenthesis() {return tokenType == TokenType.OPEN_PARENTHESIS;}

    public boolean isClosedParenthesis() {return tokenType == TokenType.CLOSE_PARENTHESIS;}
}