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

import java.util.List;
import org.parosproxy.paros.network.HttpMessage;

// todo support for evidence
/** Represents a rule violation */
public class Violation {
    private String ruleName;
    private String description;
    private HttpMessage triggeringMsg;
    private List<HttpMessage> evidenceMessages;

    public Violation(
            String ruleName,
            String description,
            HttpMessage triggeringMsg,
            List<HttpMessage> evidenceMessages) {
        this.ruleName = ruleName;
        this.description = description;
        this.triggeringMsg = triggeringMsg;
        this.evidenceMessages = evidenceMessages;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getDescription() {
        return description;
    }

    public HttpMessage getTriggeringMsg() {
        return triggeringMsg;
    }

    public String getTitle() {
        return String.format("Rule_%s violated", ruleName);
    }

    public String getUri() {
        return getTriggeringMsg().getRequestHeader().getURI().toString();
    }
}
