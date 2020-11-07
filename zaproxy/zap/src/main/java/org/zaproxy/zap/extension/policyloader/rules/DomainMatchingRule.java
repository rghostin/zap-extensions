package org.zaproxy.zap.extension.policyloader.rules;


import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is a rule for matching domains from a given list
 */
public class DomainMatchingRule implements Rule {

    @Override
    public String getName() {
        return "Domain_matching_rule";
    }

    @Override
    public String getDescription() {
        return "The request is going to a flagged domain.";
    }

    /**
     * Returns for domains' string from a given list
     * @return Returns for domains' string from a given list
     */
    private List<String> getFlaggedDomains() {
        return new ArrayList<>(Arrays.asList(
                "zerohedge.com",
                "cern.ch",
                "imdb.com"
        ));
    }

    /**
     * Returns for domains' regex from a given list
     * @return Returns for domains' regex from a given list
     */
    private ArrayList<Pattern> getRegexDomains() {
        ArrayList<Pattern> regFlaggedDomains = new ArrayList<Pattern>();
        for (String domain : getFlaggedDomains()) {
            Pattern pattern = Pattern.compile(
                    "^(?:[a-z0-9]+[.])*" + domain + "$",
                    Pattern.CASE_INSENSITIVE);
            regFlaggedDomains.add(pattern);
        }
        return regFlaggedDomains;
    }

    /**
     * Checks whether the HttpMessage violates the domain-matching rule or not
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {
        for (Pattern pattern : getRegexDomains()){
            String outgoingHostname = msg.getRequestHeader().getHostName();
            Matcher matcher = pattern.matcher(outgoingHostname);
            if (matcher.matches()){
                return true;
            }
        }
        return false;
    }
}
