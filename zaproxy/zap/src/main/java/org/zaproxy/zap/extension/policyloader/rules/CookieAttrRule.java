package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is a rule for matching cookies containing HttpOnly/Secure/SameSite
 */
public class CookieAttrRule implements Rule {

    private final String NAME = "COOKIE REQUIRED ATTRIBUTES";

    private Pattern attributes = Pattern.compile("(;?)(\\s*)HttpOnly(;?)|(;?)(\\s*)Secure(;?)|(;?)(\\s*)SameSite=(.*)(;?)");

    @Override
    public String getName() {
        return "Cookie_Attribute_Rule";
    }

    @Override
    public String getDescription() {
        return "Msg has certain attributes in Cookie";
    }

    /**
     * Checks whether the HttpMessage violates the cookies-matching rule or not
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {

        String cookie = msg.getCookieParamsAsString();

        Matcher matcher = attributes.matcher(cookie);

        if(!matcher.find()) {
            return true;
        }

        return false;
    }
}
