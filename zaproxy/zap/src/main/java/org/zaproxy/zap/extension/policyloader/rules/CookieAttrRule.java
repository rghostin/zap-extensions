/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** This is a rule for matching cookies containing HttpOnly/Secure/SameSite */
public class CookieAttrRule implements Rule {

    private final String NAME = "COOKIE REQUIRED ATTRIBUTES";

    private Pattern attributes =
            Pattern.compile(
                    "(;?)(\\s*)HttpOnly(;?)|(;?)(\\s*)Secure(;?)|(;?)(\\s*)SameSite=(.*)(;?)");

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
     *
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {

        String cookie = msg.getCookieParamsAsString();

        Matcher matcher = attributes.matcher(cookie);

        if (!matcher.find()) {
            return true;
        }

        return false;
    }
}
