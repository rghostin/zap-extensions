package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
