package org.zaproxy.zap.extension.policyloader.rules;


import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;


import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
