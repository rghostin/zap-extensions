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

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.predicate.FieldType;
import org.zaproxy.zap.extension.dslpolicyloader.predicate.HttpPredicateBuilder;
import org.zaproxy.zap.extension.dslpolicyloader.predicate.TransmissionType;

class OrOperatorTest {

    AndOperator andOperator;
    NotOperator notOperator;
    OrOperator orOperator;
    List<Predicate<HttpMessage>> httpPredicates;

    @BeforeEach
    void setup() {
        andOperator = new AndOperator();
        notOperator = new NotOperator();
        orOperator = new OrOperator();
        HttpPredicateBuilder httpPredicateBuilder = new HttpPredicateBuilder();
        httpPredicates = new ArrayList<>();
        Pattern firstPattern = Pattern.compile("hacker", Pattern.CASE_INSENSITIVE);
        Pattern secondPattern = Pattern.compile("123", Pattern.CASE_INSENSITIVE);
        httpPredicates.add(
                httpPredicateBuilder.build(TransmissionType.REQUEST, FieldType.BODY, firstPattern));
        httpPredicates.add(
                httpPredicateBuilder.build(
                        TransmissionType.REQUEST, FieldType.BODY, secondPattern));
    }

    @Test
    void hasHigherPrecedenceOver() {
        assertFalse(orOperator.hasHigherPrecedenceOver(andOperator));
        assertFalse(orOperator.hasHigherPrecedenceOver(notOperator));
    }

    @Test
    void getArity() {
        assertEquals(2, orOperator.getArity());
    }

    @Test
    void isLeftAssociative() {
        assertTrue(orOperator.isLeftAssociative());
    }

    @Test
    void operate() {
        Predicate<HttpMessage> predicate = orOperator.operate(httpPredicates);
        assertTrue(predicate.test(createHttpMsg("hacker123")));
        assertTrue(predicate.test(createHttpMsg("hacker")));
        assertTrue(predicate.test(createHttpMsg("123")));
    }

    private HttpMessage createHttpMsg(String keyword) {
        try {
            HttpMessage msg = new HttpMessage(new URI("http://example.com/", true));
            msg.setRequestBody(String.format("<html><head></head><body>%s</body><html>", keyword));
            return msg;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
