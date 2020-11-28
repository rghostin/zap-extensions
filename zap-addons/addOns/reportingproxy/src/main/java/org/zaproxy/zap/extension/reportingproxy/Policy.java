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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.parosproxy.paros.network.HttpMessage;

/** Policy of rules */
public class Policy {

    private String name;
    private Set<Rule> rules = new HashSet<>();

    public Policy(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    private boolean ruleExists(String ruleName) {
        for (Rule rule : rules) {
            if (rule.getName().equals(ruleName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Add a {@Code Rule} to the policy
     *
     * @param rule : the rule to be added
     */
    public void addRule(Rule rule) {
        if (ruleExists(rule.getName())) {
            return;
        }
        rules.add(rule);
    }

    /**
     * Remove the rule from the policy
     *
     * @param rule : the rule to be removed
     */
    public void removeRule(Rule rule) {
        if (!ruleExists(rule.getName())) {
            return;
        }
        rules.remove(rule);
    }

    public Set<Rule> getRules() {
        return rules;
    }

    /**
     * Given an http message, checks whether the policy is violated by checking if any of the
     * registered rules is violated
     *
     * @param msg : the http message
     * @return a list of {@code Violation} encountered
     */
    public List<Violation> checkViolations(HttpMessage msg) {
        List<Violation> violations = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.isViolated(msg)) {
                violations.add(new Violation(getName(), rule, msg));
            }
        }
        return violations;
    }
}
