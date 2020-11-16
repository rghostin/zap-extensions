package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.parosproxy.paros.network.HttpMessage;

import java.util.regex.Pattern;

public class RequestHeaderCheck extends Check {

    public RequestHeaderCheck(Pattern pattern) {
        super(pattern);
    }

    @Override
    String getFieldOfOperation(HttpMessage msg) {
        return msg.getRequestHeader().toString();
    }
}
