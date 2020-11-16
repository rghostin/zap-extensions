package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

import org.zaproxy.zap.extension.dslpolicyloader.checks.HttpPredicate;

import java.util.List;

public class NotOperator implements HttpPredicateOperator {
    @Override
    public int getPrecedence() {
        return 3;
    }

    @Override
    public int getArity() {
        return 1;
    }

    @Override
    public HttpPredicate operate(List<HttpPredicate> httpPredicates) {
        assert httpPredicates.size() == getArity();
        return (HttpPredicate) httpPredicates.get(0).negate();
    }

    @Override
    public boolean isLeftAssociative() {
        return false;
    }
}
