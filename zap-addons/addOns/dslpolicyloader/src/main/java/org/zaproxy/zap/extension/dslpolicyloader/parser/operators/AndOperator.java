package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

public class AndOperator implements Operator {
    @Override
    public int getPrecedence() {
        return 2;
    }
}
