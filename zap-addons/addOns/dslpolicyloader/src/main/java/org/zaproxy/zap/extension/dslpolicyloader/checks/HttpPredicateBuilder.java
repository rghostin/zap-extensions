package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.parosproxy.paros.network.HttpMessage;

import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpPredicateBuilder {
    private final TransmissionType transmissionType;
    private final FieldOfOperation fieldOfOperation;
    private final Pattern pattern;

    public HttpPredicateBuilder(TransmissionType transmissionType, FieldOfOperation fieldOfOperation, Pattern pattern) {
        this.transmissionType = transmissionType;
        this.fieldOfOperation = fieldOfOperation;
        this.pattern = pattern;
    }

    private Function<HttpMessage, String> getFieldFct() {
        if (transmissionType == TransmissionType.REQUEST && fieldOfOperation == FieldOfOperation.HEADER) {
            return (msg) -> msg.getRequestHeader().toString();
        } else if (transmissionType == TransmissionType.REQUEST && fieldOfOperation == FieldOfOperation.BODY) {
            return (msg) -> msg.getRequestBody().toString();
        } else if (transmissionType == TransmissionType.RESPONSE && fieldOfOperation == FieldOfOperation.HEADER) {
            return (msg) -> msg.getResponseHeader().toString();
        } else if (transmissionType == TransmissionType.RESPONSE && fieldOfOperation == FieldOfOperation.BODY) {
            return (msg) -> msg.getResponseBody().toString();
        } else {
            throw new IllegalStateException("Logic error");
        }
    }

    public Predicate<HttpMessage> build() {
        return new Predicate<HttpMessage>() {
            private final Function<HttpMessage, String> getField = getFieldFct();

            @Override
            public boolean test(HttpMessage msg) {
                String field = getField.apply(msg);
                Matcher matcher = pattern.matcher(field);
                return  matcher.find();
            }
        };
    }

}
