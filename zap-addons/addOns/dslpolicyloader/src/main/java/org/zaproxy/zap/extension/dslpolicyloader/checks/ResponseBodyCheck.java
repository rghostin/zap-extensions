package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.parosproxy.paros.network.HttpMessage;

import java.util.regex.Pattern;

public class ResponseBodyCheck extends Check {

    public ResponseBodyCheck(Pattern pattern) {
        super(pattern);
    }

    @Override
    String getFieldOfOperation(HttpMessage msg) {
        return msg.getRequestBody().toString();
    }
}
