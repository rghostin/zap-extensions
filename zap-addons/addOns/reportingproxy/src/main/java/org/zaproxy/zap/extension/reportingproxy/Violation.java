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
package org.zaproxy.zap.extension.reportingproxy;

import org.parosproxy.paros.network.HttpMessage;

// todo support for evidence
/** Represents a rule violation */
public class Violation {
    private String ruleName;
    private String description;
    private HttpMessage msg;

    public Violation(String ruleName, String description, HttpMessage msg) {
        this.ruleName = ruleName;
        this.description = description;
        this.msg = msg;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getDescription() {
        return description;
    }

    public HttpMessage getMsg() {
        return msg;
    }

    public String getTitle() {
        return String.format("Rule_%s violated", ruleName);
    }

    public String getUri() {
        return getMsg().getRequestHeader().getURI().toString();
    }
}
