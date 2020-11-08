package org.zaproxy.zap.extension.policyloader;

import org.parosproxy.paros.network.HttpMessage;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

    public void addRule(Rule rule) {
        if (ruleExists(rule.getName())) {
            return;
        }
        rules.add(rule);
    }

    public void removeRule(Rule rule) {
        if (! ruleExists(rule.getName())) {
            return;
        }
        rules.remove(rule);
    }

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
