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

/** Represents a rule violation */
public class Violation {
    private String policyName;
    private String ruleName;
    private String description;
    private HttpMessage msg;

    public Violation(String policyName, Rule rule, HttpMessage msg) {
        this.policyName = policyName;
        this.ruleName = rule.getName();
        this.description = rule.getDescription();
        this.msg = msg;
    }

    public String getPolicyName() {
        return policyName;
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
        return String.format("Policy_%s.Rule_%s violated", policyName, ruleName);
    }

    public String getUri() {
        return getMsg().getRequestHeader().getURI().toString();
    }
}
