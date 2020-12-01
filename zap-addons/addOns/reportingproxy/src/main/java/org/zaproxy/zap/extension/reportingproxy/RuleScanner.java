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
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.reportingproxy.exceptions.DuplicateRuleException;
import org.zaproxy.zap.extension.reportingproxy.exceptions.RuleNotFoundException;

/** Responsible of checking passively whether any loaded rule is violated */
public class RuleScanner extends PluginPassiveScanner {
    private Set<Rule> rules = new HashSet<>();
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
        return "Rule scanner";
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
                .setMessage(violation.getTriggeringMsg())
                .setUri(violation.getTriggeringUri())
                .setEvidence(violation.getEvidenceUris())
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
     * Scan HTTP messages upon reception If any rule is violated raise an alert and store the
     * violation in history
     *
     * @param msg
     * @param id
     * @param source
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        for (Rule rule : rules) {
            Violation violation = rule.checkViolation(msg);
            if (violation != null) {
                violationHistory.add(violation);
                raiseAlert(violation);
            }
        }
    }

    /**
     * Checks whether a rule with a given name is loaded
     *
     * @param ruleName : the rule name
     * @return : boolean
     */
    public boolean hasRule(String ruleName) {
        for (Rule rule : rules) {
            if (rule.getName().equals(ruleName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Add a new rule
     *
     * @param rule: the rule to be added
     * @throws DuplicateRuleException : a rule with same name already exists
     */
    public void addRule(Rule rule) throws DuplicateRuleException {
        if (hasRule(rule.getName())) {
            throw new DuplicateRuleException();
        }
        rules.add(rule);
    }

    /**
     * Remove a rule
     *
     * @param ruleName the rule name
     * @throws RuleNotFoundException : a rule with this name is not registered
     */
    public void removeRule(String ruleName) throws RuleNotFoundException {
        if (!hasRule(ruleName)) {
            throw new RuleNotFoundException();
        }
        rules.removeIf(rule -> rule.getName().equals(ruleName));
    }
}
