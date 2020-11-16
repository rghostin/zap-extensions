package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

import org.parosproxy.paros.network.HttpMessage;

import java.util.List;
import java.util.function.Predicate;

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
    public Predicate<HttpMessage> operate(List<Predicate<HttpMessage>> httpPredicates) {
        assert httpPredicates.size() == getArity();
        return httpPredicates.get(0).negate();
    }

    @Override
    public boolean isLeftAssociative() {
        return false;
    }
}
