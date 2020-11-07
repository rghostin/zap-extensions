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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.policyloader.exceptions.PolicyNotFoundException;

/** A container for holding policies */
public class PolicyContainer {
    private Map<String, Set<Rule>> policies = new HashMap<>();

    /**
     * Checks whether the selected policy is exist
     *
     * @param policyName the policy that will be checked
     * @return true if the policy exists in the container, false if not
     */
    private boolean policyExists(String policyName) {
        return policies.containsKey(policyName);
    }

    /**
     * Adds a new policy to the policy container
     *
     * @param policyName the name of the policy that to be added to the container
     * @param rules the rules of the policy that to be added to the container
     * @throws DuplicatePolicyException is thrown when the policy is duplicated
     */
    public void addPolicy(String policyName, Set<Rule> rules) throws DuplicatePolicyException {
        if (policyExists(policyName)) {
            throw new DuplicatePolicyException();
        }
        policies.put(policyName, rules);
    }

    /**
     * Removes a policy by its name from the policy container
     *
     * @param policyName the name of the policy that to be removed from the container
     * @throws PolicyNotFoundException is thrown when the policy is not exist
     */
    public void removePolicy(String policyName) throws PolicyNotFoundException {
        if (!policyExists(policyName)) {
            throw new PolicyNotFoundException();
        }
        policies.remove(policyName);
    }

    /**
     * Returns the rules of a policy by its name
     *
     * @param policyName the name of the policy that is selected
     * @return the rules of the policy that is selected
     * @throws PolicyNotFoundException is thrown when the policy is not exist
     */
    public Set<Rule> getPolicyRules(String policyName) throws PolicyNotFoundException {
        if (!policyExists(policyName)) {
            throw new PolicyNotFoundException();
        }
        return policies.get(policyName);
    }

    /**
     * Returns a set containing all policies in the container
     *
     * @return Returns a set containing all policies in the container
     */
    public Set<String> getPolicies() {
        return policies.keySet();
    }
}
