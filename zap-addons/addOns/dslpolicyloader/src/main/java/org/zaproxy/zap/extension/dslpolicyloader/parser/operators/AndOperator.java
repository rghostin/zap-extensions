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

public class AndOperator implements HttpPredicateOperator {
    @Override
    public int getArity() {
        return 2;
    }

    @Override
    public int getPrecedence() {
        return 2;
    }

    @Override
    public boolean isLeftAssociative() {
        return true;
    }

    @Override
    public Predicate<HttpMessage> operate(List<Predicate<HttpMessage>> httpPredicates) {
        assert httpPredicates.size() == getArity();
        Predicate<HttpMessage> pred1 = httpPredicates.get(0);
        Predicate<HttpMessage> pred2 = httpPredicates.get(1);
        return pred1.and(pred2);
    }
}
