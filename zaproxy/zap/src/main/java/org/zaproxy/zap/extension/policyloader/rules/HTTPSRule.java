package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HTTPSRule implements Rule {

    private final String MY_APP_HOST = "cern.ch";

    private Pattern reMyappDomain = Pattern.compile(
            "^(?:[a-z0-9]+[.])*" + MY_APP_HOST + "$",
            Pattern.CASE_INSENSITIVE
        );

    @Override
    public String getName() {
        return "HTTPS";
    }
    @Override
    public String getDescription() {
        return String.format("The HTTP message going to %s is not secure.", MY_APP_HOST);
    }

    private boolean isGoingToMyApp(HttpMessage msg) {
        String outgoingHostname = msg.getRequestHeader().getHostName();
        Matcher matcher = reMyappDomain.matcher(outgoingHostname);
        return matcher.matches();
    }

    @Override
    public boolean isViolated(HttpMessage msg) {
        if (isGoingToMyApp(msg)) {
            return ! msg.getRequestHeader().isSecure();
        }
        return false;
    }
}
