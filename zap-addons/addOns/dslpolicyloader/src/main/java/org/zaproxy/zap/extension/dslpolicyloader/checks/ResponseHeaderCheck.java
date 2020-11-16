package org.zaproxy.zap.extension.dslpolicyloader.checks;

import org.parosproxy.paros.network.HttpMessage;

import java.util.regex.Pattern;

public class ResponseHeaderCheck extends Check {

    public ResponseHeaderCheck(Pattern pattern) {
        super(pattern);
    }

    @Override
    String getFieldOfOperation(HttpMessage msg) {
        return msg.getResponseHeader().toString();
    }
}
