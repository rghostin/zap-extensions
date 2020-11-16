package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

public class NotOperator implements Operator {
    @Override
    public int getPrecedence() {
        return 3;
    }

    @Override
    public boolean isLeftAssociative() {
        return false;
    }
}
