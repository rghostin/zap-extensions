package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class KeywordMatchingRule implements Rule {

    @Override
    public String getName() {
        return "Keyword_matching_rule";
    }

    @Override
    public boolean isActiveForSend() {
        return true;
    }

    @Override
    public boolean isActiveForReceive() {
        return true;
    }

    private List<String> getFlaggedKeywords() {
        return new ArrayList<>(Arrays.asList(
                "hacker",
                "phishing",
                "better"
        ));
    }

    @Override
    public boolean isViolated(HttpMessage msg) {
        String bodySend = msg.getRequestBody().toString();
        String bodyReceive = msg.getResponseBody().toString();
        String body = bodySend + bodyReceive;

        for (String keyword : getFlaggedKeywords()) {
            if (body.contains(keyword)) {
                return true;
            }
        }
        return false;
    }
}
