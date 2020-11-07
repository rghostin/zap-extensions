package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CookieAttrRule implements Rule {

    private final String NAME = "COOKIE REQUIRED ATTRIBUTES";

    private Pattern httpOnly = Pattern.compile("(;?)(\\s*)HttpOnly(;?)");
    private Pattern secure = Pattern.compile("(;?)(\\s*)Secure(;?)");
    private Pattern sameSite = Pattern.compile("(;?)(\\s*)SameSite=(None|Strict|Lax)(;?)");

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

        Matcher matcherHttp = httpOnly.matcher(cookie);
        Matcher matcherSec = secure.matcher(cookie);
        Matcher matcherSame = sameSite.matcher(cookie);

        if(!matcherHttp.find() || !matcherSec.find() || !matcherSame.find()) {
            return true;
        }

        return false;
    }
}