package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

public interface Operator {
    int getPrecedence();
    boolean isLeftAssociative();

    default boolean hasHigherPrecedenceOver(Operator otherOp) {
        if (getPrecedence() > otherOp.getPrecedence()) {
            return true;
        } else if (getPrecedence() == otherOp.getPrecedence()) {
            return isLeftAssociative();
        } else {
            return false;
        }
    }
}
