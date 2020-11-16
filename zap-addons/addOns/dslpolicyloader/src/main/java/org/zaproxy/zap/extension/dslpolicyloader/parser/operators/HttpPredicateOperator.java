package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

import org.zaproxy.zap.extension.dslpolicyloader.checks.HttpPredicate;

import java.util.List;

public interface HttpPredicateOperator {
    int getPrecedence();
    boolean isLeftAssociative();

    int getArity();

    default boolean isUnary() {return getArity()==1;}

    default boolean isBinary() {return getArity()==2;}

    default boolean hasHigherPrecedenceOver(HttpPredicateOperator otherOp) {
        if (getPrecedence() > otherOp.getPrecedence()) {
            return true;
        } else if (getPrecedence() == otherOp.getPrecedence()) {
            return isLeftAssociative();
        } else {
            return false;
        }
    }

    HttpPredicate operate(List<HttpPredicate> httpPredicates);
}
