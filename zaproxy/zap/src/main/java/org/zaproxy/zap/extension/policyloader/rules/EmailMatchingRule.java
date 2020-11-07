package org.zaproxy.zap.extension.policyloader.rules;


import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;


import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is a rule for matching the generic email address format
 */
public class EmailMatchingRule implements Rule {

    private final String REGEX_EMAIL = "(.{1,64})@(.{1,255})\\.(.{1,24})";
    private Pattern pattern = Pattern.compile(REGEX_EMAIL);

    @Override
    public String getName() {
        return "Email_matching_rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP message contains an email address.";
    }

    /**
     * Checks whether the HttpMessage violates the email-matching rule or not
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {
        String bodySend = msg.getRequestBody().toString();
        String bodyReceive = msg.getResponseBody().toString();
        String body = bodySend + bodyReceive;
        Matcher matcher = pattern.matcher(body);
        if (matcher.find()) {
            return true;
        }
        return false;
    }
}
