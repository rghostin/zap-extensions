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

import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.policyloader.exceptions.PolicyNotFoundException;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class PolicyContainer {
    private Map<String, Set<Rule>> policies = new HashMap<>();

    private boolean policyExists(String policyName) {
        return policies.containsKey(policyName);
    }

    public void addPolicy(String policyName, Set<Rule> rules) throws DuplicatePolicyException {
        if (policyExists(policyName)) {
            throw new DuplicatePolicyException();
        }
        policies.put(policyName, rules);
    }

    public void removePolicy(String policyName) throws PolicyNotFoundException {
        if (!policyExists(policyName)) {
            throw new PolicyNotFoundException();
        }
        policies.remove(policyName);
    }

    public Set<Rule> getPolicyRules(String policyName) throws PolicyNotFoundException {
        if (!policyExists(policyName)) {
            throw new PolicyNotFoundException();
        }
        return policies.get(policyName);
    }

    public Set<String> getPolicies() {
        return policies.keySet();
    }
}
