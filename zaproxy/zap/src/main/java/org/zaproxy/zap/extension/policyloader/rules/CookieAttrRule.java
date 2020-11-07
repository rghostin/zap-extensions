package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
