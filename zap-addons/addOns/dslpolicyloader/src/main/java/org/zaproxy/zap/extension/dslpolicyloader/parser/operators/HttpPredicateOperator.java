/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.dslpolicyloader.parser.operators;

import java.util.List;
import java.util.function.Predicate;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Represents an operation on Http predicates Precedence, associativity and arity have been defined
 * to be compatible with the shunting yard algorithm
 */
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

    /**
     * construct the predicate which when tested is equal to the operation performed on all the
     * given predicates
     *
     * @param httpPredicates : list of predicates to evaluate
     * @return: the predicate
     */
    Predicate<HttpMessage> operate(List<Predicate<HttpMessage>> httpPredicates);
}
