package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

import org.parosproxy.paros.network.HttpMessage;

import java.util.List;
import java.util.function.Predicate;

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
    public Predicate<HttpMessage> operate(List<Predicate<HttpMessage> > httpPredicates) {
        assert httpPredicates.size() == getArity();
        Predicate<HttpMessage>  pred1 = httpPredicates.get(0);
        Predicate<HttpMessage>  pred2 = httpPredicates.get(1);
        return pred1.or(pred2);
    }

}
