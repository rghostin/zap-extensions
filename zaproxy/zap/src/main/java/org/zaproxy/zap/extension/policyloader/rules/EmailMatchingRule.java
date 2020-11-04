package org.zaproxy.zap.extension.policyloader.rules;


import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EmailMatchingRule implements Rule {

    @Override
    public String getName() {
        return "Email_matching_rule";
    }

    @Override
    public boolean isActiveForSend() {
        return true;
    }

    @Override
    public boolean isActiveForReceive() {
        return true;
    }

    String regex = "^(.+)@(.+)\\.(.+)$";
    Pattern pattern = Pattern.compile(regex);

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
