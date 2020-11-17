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
package org.zaproxy.zap.extension.dslpolicyloader;

import org.parosproxy.paros.network.HttpMessage;

import javax.print.DocFlavor;
import java.util.function.Predicate;


public class Rule {
    private final String name;
    private final String description;
    private final Predicate<HttpMessage> predicate;

    public Rule(String name, String description, Predicate<HttpMessage> predicate) {
        this.name = name;
        this.description = description;
        this.predicate = predicate;
    }

    /**
     * @return Returns this rule's name
     */
    public String getName() { return name; }

    /**
     * @return Returns this rule's description
     */
    public String getDescription() { return description; }

    /**
     * Checks whether the HttpMessage violates the rule
     * The violation check is done by invoking predicate.test
     * @param msg the HttpMessage that will be tested
     * @return true if the HttpMessage violates the rule, false if not
     */
    public boolean isViolated(HttpMessage msg) {
        return predicate.test(msg);
    }
}
