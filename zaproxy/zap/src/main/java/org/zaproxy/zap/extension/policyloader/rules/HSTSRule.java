package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is a rule for checking the HSTS header exist in the response HTTPMessage
 */
public class HSTSRule implements Rule {

    private final String HSTS_HEADER_NAME = "Strict-Transport-Security";
    private final Pattern hstsPattern = Pattern.compile(
                "^max-age=(\\d+)(?:\\s*;\\s*includeSubDomains)?(?:\\s*;\\s*preload)?$"
            );

    @Override
    public String getName() {
        return "HSTS_Rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP response message does not enforce HSTS.";
    }

    /**
     * Checks whether the HttpMessage violates the HSTS rule rule or not
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {
        String hstsHeader = msg.getResponseHeader().getHeader(HSTS_HEADER_NAME);
        if (hstsHeader == null) {
            return true;
        }
        hstsHeader = hstsHeader.trim();
        Matcher hstsMatcher = hstsPattern.matcher(hstsHeader);
        if (! hstsMatcher.matches()) {
            return true;
        }
        return false;
    }
}
