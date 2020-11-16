package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

public class OrOperator implements Operator {
    @Override
    public int getPrecedence() {
        return 1;
    }
}
