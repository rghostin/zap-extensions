package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

import org.parosproxy.paros.network.HttpMessage;

import java.util.List;
import java.util.function.Predicate;

public interface HttpPredicateOperator {
    int getPrecedence();
    boolean isLeftAssociative();

    int getArity();

    default boolean hasHigherPrecedenceOver(HttpPredicateOperator otherOp) {
        if (getPrecedence() > otherOp.getPrecedence()) {
            return true;
        } else if (getPrecedence() == otherOp.getPrecedence()) {
            return isLeftAssociative();
        } else {
            return false;
        }
    }

    Predicate<HttpMessage> operate(List<Predicate<HttpMessage>> httpPredicates);
}
