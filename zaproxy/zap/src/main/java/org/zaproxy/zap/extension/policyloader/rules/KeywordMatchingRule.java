package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This is a rule for matching bad keywords
 */
public class KeywordMatchingRule implements Rule {

    @Override
    public String getName() {
        return "Keyword_matching_rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP message contains a flagged keyword.";
    }

    /**
     * Returns the keywords to flag
     * @return Returns the keywords to flag
     */
    public List<String> getFlaggedKeywords() {
        return new ArrayList<>(Arrays.asList(
                "hacker",
                "phishing",
                "eavesdropping",
                "hacking"
        ));
    }

    /**
     * Checks whether the HttpMessage violates the keyword-matching rule or not
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
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
