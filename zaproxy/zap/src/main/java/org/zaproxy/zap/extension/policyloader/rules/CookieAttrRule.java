package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CookieAttrRule implements Rule {

    private final String NAME = "COOKIE REQUIRED ATTRIBUTES";

    private List<String> getNeededAttrs() {
        return new ArrayList<>(Arrays.asList(
                "HttpOnly",
                "Secure",
                "SameSite"
        ));
    }

    @Override
    public String getName() {
        return "Cookie_Attribute_Rule";
    }

    @Override
    public boolean isActiveForSend() {
        return false;
    }

    @Override
    public boolean isActiveForReceive() {
        return true;
    }

    @Override
    public boolean isViolated(HttpMessage msg) {

        String cookie = msg.getCookieParamsAsString();

        for (String keyword : getNeededAttrs()) {
            if (cookie.contains(keyword)) {
                return true;
            }
        }

        return false;
    }
}
