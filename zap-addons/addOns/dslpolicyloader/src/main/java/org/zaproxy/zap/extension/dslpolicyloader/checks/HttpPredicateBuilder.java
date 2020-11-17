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
package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.parosproxy.paros.network.HttpMessage;

import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Responsible for building a HttpMessage predicate
 */
public class HttpPredicateBuilder {

//    private Function<HttpMessage, String> getFieldFct() { // todo try functional
//        Function<HttpMessage, String> f;
//        if (transmissionType == TransmissionType.REQUEST && fieldOfOperation == FieldType.HEADER) {
//            ;
//        f =  (msg) -> msg.getRequestHeader().toString();
//        } else if (transmissionType == TransmissionType.REQUEST && fieldOfOperation == FieldType.BODY) {
//            f = (msg) -> msg.getRequestBody().toString();
//        } else if (transmissionType == TransmissionType.RESPONSE && fieldOfOperation == FieldType.HEADER) {
//            f = (msg) -> msg.getResponseHeader().toString();
//        } else if (transmissionType == TransmissionType.RESPONSE && fieldOfOperation == FieldType.BODY) {
//            f = (msg) -> msg.getResponseBody().toString();
//        } else {
//            throw new IllegalStateException("Logic error");
//        }
//        return f;
//    }

    /**
     * Builds a HttpMessage Predicate given matching constraints
     * @param transmissionType : TransmissionType {REQUEST|RESPONSE}
     * @param fieldType : FieldType {HEADER|BODY}
     * @param pattern: pattern to match
     * @return : An HttpMessage Predicate that tests true if a given HttpMessage
     * matches the pattern in the concerned field
     */
    public Predicate<HttpMessage> build(TransmissionType transmissionType, FieldType fieldType, Pattern pattern) {
        return new Predicate<HttpMessage>() {
            private final TransmissionType transmissionType_ = transmissionType;
            private final FieldType fieldType_ = fieldType;
            private final Pattern pattern_ = pattern;

            private String getField(HttpMessage msg) {
                String field;
                if (transmissionType_ == TransmissionType.REQUEST && fieldType_ == FieldType.HEADER) {
                    field = msg.getRequestHeader().toString();
                } else if (transmissionType_ == TransmissionType.REQUEST && fieldType_ == FieldType.BODY) {
                    field = msg.getRequestBody().toString();
                } else if (transmissionType_ == TransmissionType.RESPONSE && fieldType_ == FieldType.HEADER) {
                    field = msg.getResponseHeader().toString();
                } else if (transmissionType_ == TransmissionType.RESPONSE && fieldType_ == FieldType.BODY) {
                    field =  msg.getResponseBody().toString();
                } else {
                    throw new IllegalStateException("Logic error");
                }
                return field;
            }

            @Override
            public boolean test(HttpMessage msg) {
                String field = getField(msg);
                Matcher matcher = pattern_.matcher(field);
                return matcher.find();
            }
        };
    }

}
