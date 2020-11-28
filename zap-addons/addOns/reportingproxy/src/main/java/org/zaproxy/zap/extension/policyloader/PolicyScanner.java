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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.policyloader.exceptions.PolicyNotFoundException;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Responsible of checking passively whether any loaded policy is violated */
public class PolicyScanner extends PluginPassiveScanner {
    private Set<Policy> policies = new HashSet<>();
    private List<Violation> violationHistory = new ArrayList<>();

    @Override
    public int getPluginId() {
        return 500001;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // do nothing here
    }

    @Override
    public String getName() {
        return "Policy scanner";
    }

    /**
     * Log an alert in the Zap gui
     *
     * @param violation : the violation to logged
     */
    private void raiseAlert(Violation violation) {
        newAlert()
                .setName(violation.getTitle())
                .setDescription(violation.getDescription())
                .setMessage(violation.getMsg())
                .setUri(violation.getUri())
                .raise();
    }

    /** @return the history of all violations encountered */
    public List<Violation> getViolationHistory() {
        return violationHistory;
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // the work is done when the message is received
    }

    /**
     * Scan HTTP messages upon reception If any policy is violated raise an alert and store the
     * violation in history
     *
     * @param msg
     * @param id
     * @param source
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        for (Policy policy : policies) {
            List<Violation> violations = policy.checkViolations(msg);

            violationHistory.addAll(violations);

            for (Violation violation : violations) {
                raiseAlert(violation);
            }
        }
    }

    /**
     * Checks whether a policy zith a given name is loaded
     *
     * @param policyName : the policy name
     * @return : boolean
     */
    public boolean hasPolicy(String policyName) {
        for (Policy policy : policies) {
            if (policy.getName().equals(policyName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Add a new policy
     *
     * @param policy: the policy to be added
     * @throws DuplicatePolicyException : a policy with same name already exists
     */
    public void addPolicy(Policy policy) throws DuplicatePolicyException {
        if (hasPolicy(policy.getName())) {
            throw new DuplicatePolicyException();
        }
        policies.add(policy);
    }

    /**
     * Remove a policy
     *
     * @param policyName the policy name
     * @throws PolicyNotFoundException : a policy with this name is not registered
     */
    public void removePolicy(String policyName) throws PolicyNotFoundException {
        if (!hasPolicy(policyName)) {
            throw new PolicyNotFoundException();
        }
        policies.removeIf(policy -> policy.getName().equals(policyName));
    }
}
