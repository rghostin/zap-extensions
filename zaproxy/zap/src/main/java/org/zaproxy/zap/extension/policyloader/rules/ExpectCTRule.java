package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExpectCTRule implements Rule {

    private final String EXPECT_HEADER_NAME = "Expect-CT";
    private final Pattern expectPattern = Pattern.compile("max-age=(\\d+)");
    private final String MY_APP_HOST = "cern.ch";

    private Pattern reMyappDomain = Pattern.compile(
            "^(?:[a-z0-9]+[.])*" + MY_APP_HOST + "$",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public String getName() {
        return "ExpectCT_Rule";
    }

    @Override
    public String getDescription() {
        return "The HTTP response message does not enforce ExpectCT Rule.";
    }

    private boolean isGoingToMyApp(HttpMessage msg) {
        String outgoingHostname = msg.getRequestHeader().getHostName();
        Matcher matcher = reMyappDomain.matcher(outgoingHostname);
        return matcher.matches();
    }

    @Override
    public boolean isViolated(HttpMessage msg) {
        if (isGoingToMyApp(msg)) {
            String expectHeader = msg.getResponseHeader().getHeader(EXPECT_HEADER_NAME);
            if (expectHeader == null) {
                return true;
            }
            expectHeader = expectHeader.trim();
            Matcher expectMatcher = expectPattern.matcher(expectHeader);
            if (! expectMatcher.find()) {
                return true;
            }
        }
        return false;
    }
}
