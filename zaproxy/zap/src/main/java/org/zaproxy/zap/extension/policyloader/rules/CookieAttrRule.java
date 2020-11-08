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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

/** A rule for checking whether cookies have security flags enabled */
public class CookieAttrRule implements Rule {

    private final Pattern httpOnly = Pattern.compile("(;?)(\\s*)HttpOnly(;?)");
    private final Pattern secure = Pattern.compile("(;?)(\\s*)Secure(;?)");
    private final Pattern sameSite = Pattern.compile("(;?)(\\s*)SameSite=(None|Strict|Lax)(;?)");

    @Override
    public String getName() {
        return "Cookie_Attribute_Rule";
    }

    @Override
    public String getDescription() {
        return "Msg has certain attributes in Cookie";
    }

    /**
     * Checks whether the cookies in message (request or response) have all security flags on
     *
     * @param msg the HttpMessage that will be checked
     * @return
     */
    @Override
    public boolean isViolated(HttpMessage msg) {

        String cookie = msg.getCookieParamsAsString();

        Matcher matcherHttp = httpOnly.matcher(cookie);
        Matcher matcherSec = secure.matcher(cookie);
        Matcher matcherSame = sameSite.matcher(cookie);

        if (!matcherHttp.find() || !matcherSec.find() || !matcherSame.find()) {
            return true;
        }

        return false;
    }
}
