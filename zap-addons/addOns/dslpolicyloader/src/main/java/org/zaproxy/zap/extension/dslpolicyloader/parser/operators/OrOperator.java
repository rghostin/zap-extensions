package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

import org.zaproxy.zap.extension.dslpolicyloader.checks.HttpPredicate;

import java.util.List;

public class OrOperator implements HttpPredicateOperator {

    @Override
    public int getArity() {
        return 2;
    }

    @Override
    public int getPrecedence() {
        return 1;
    }

    @Override
    public boolean isLeftAssociative() {
        return true;
    }

    @Override
    public HttpPredicate operate(List<HttpPredicate> httpPredicates) {
        assert httpPredicates.size() == getArity();
        HttpPredicate pred1 = httpPredicates.get(0);
        HttpPredicate pred2 = httpPredicates.get(1);
        return (HttpPredicate) pred1.or(pred2);
    }

}
