package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.parosproxy.paros.network.HttpMessage;

import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpPredicateBuilder {

//    private Function<HttpMessage, String> getFieldFct() {
//        Function<HttpMessage, String> f;
//        if (transmissionType == TransmissionType.REQUEST && fieldOfOperation == FieldOfOperation.HEADER) {
//            ;
//        f =  (msg) -> msg.getRequestHeader().toString();
//        } else if (transmissionType == TransmissionType.REQUEST && fieldOfOperation == FieldOfOperation.BODY) {
//            f = (msg) -> msg.getRequestBody().toString();
//        } else if (transmissionType == TransmissionType.RESPONSE && fieldOfOperation == FieldOfOperation.HEADER) {
//            f = (msg) -> msg.getResponseHeader().toString();
//        } else if (transmissionType == TransmissionType.RESPONSE && fieldOfOperation == FieldOfOperation.BODY) {
//            f = (msg) -> msg.getResponseBody().toString();
//        } else {
//            throw new IllegalStateException("Logic error");
//        }
//        return f;
//    }


    public Predicate<HttpMessage> build(TransmissionType transmissionType, FieldOfOperation fieldOfOperation, Pattern pattern) {
        return new Predicate<HttpMessage>() {
            private final TransmissionType transmissionType_ = transmissionType;
            private final FieldOfOperation fieldOfOperation_ = fieldOfOperation;
            private final Pattern pattern_ = pattern;

            private String getField(HttpMessage msg) { // todo try functional
                String field;
                if (transmissionType_ == TransmissionType.REQUEST && fieldOfOperation_ == FieldOfOperation.HEADER) {
                    field = msg.getRequestHeader().toString();
                } else if (transmissionType_ == TransmissionType.REQUEST && fieldOfOperation_ == FieldOfOperation.BODY) {
                    field = msg.getRequestBody().toString();
                } else if (transmissionType_ == TransmissionType.RESPONSE && fieldOfOperation_ == FieldOfOperation.HEADER) {
                    field = msg.getResponseHeader().toString();
                } else if (transmissionType_ == TransmissionType.RESPONSE && fieldOfOperation_ == FieldOfOperation.BODY) {
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
