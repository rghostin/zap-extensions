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
package org.zaproxy.zap.extension.policyloader;

import org.parosproxy.paros.network.HttpMessage;

/** This is public interface for runtime rule inspection */
public interface Rule {

    /**
     * Returns this rule's name
     *
     * @return Returns this rule's name
     */
    String getName();

    /**
     * Returns this rule's description
     *
     * @return Returns this rule's description
     */
    String getDescription();

    /**
     * Checks whether the HttpMessage violates a specific rule
     *
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    boolean isViolated(HttpMessage msg);
}
