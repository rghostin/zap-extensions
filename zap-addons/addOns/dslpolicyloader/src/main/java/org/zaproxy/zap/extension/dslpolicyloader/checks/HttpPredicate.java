package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.parosproxy.paros.network.HttpMessage;

import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpPredicate {
    private TransmissionType transmissionType;
    private FieldOfOperation fieldOfOperation;
    private Pattern pattern;

    public HttpPredicate(TransmissionType transmissionType, FieldOfOperatin fieldOfOperation, Pattern pattern) {
        this.transmissionType = transmissionType;
        this.fieldOfOperation = fieldOfOperation;
        this.pattern = pattern;
    }

    private String getFieldOfOperation(HttpMessage msg) {
        String field;
        if (transmissionType == TransmissionType.REQUEST && fieldOfOperation == FieldOfOperation.HEADER) {
            field = msg.getRequestHeader().toString();
        } else if (transmissionType == TransmissionType.REQUEST && fieldOfOperation == FieldOfOperation.BODY) {
            field = msg.getRequestBody().toString();
        } else if (transmissionType == TransmissionType.RESPONSE && fieldOfOperation == FieldOfOperation.HEADER) {
            field = msg.getResponseHeader().toString();
        } else if (transmissionType == TransmissionType.RESPONSE && fieldOfOperation == FieldOfOperation.BODY) {
            field = msg.getResponseBody().toString();
        } else {
            throw new IllegalStateException("Logic error");
        }
        return field;
    }

    public HttpPredicate(Pattern pattern) {
        this.pattern = pattern;
    }

    public boolean test(HttpMessage msg) {
        String field = getFieldOfOperation(msg);
        Matcher matcher = pattern.matcher(field);
        return  matcher.find();
    }

    HttpPredicate and(HttpPredicate predicate) {
        HttpPredicate predicate1 = new HttpPredicate() {
            public boolean test() {
                return true;
            }
        };
    }
}
