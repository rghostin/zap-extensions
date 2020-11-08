package org.zaproxy.zap.extension.policyloader;

import org.parosproxy.paros.network.HttpMessage;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Policy of rules
 */
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
     * @param rule : the rule to be removed
     */
    public void removeRule(Rule rule) {
        if (! ruleExists(rule.getName())) {
            return;
        }
        rules.remove(rule);
    }

    public Set<Rule> getRules() {
        return rules;
    }

    /**
     * Given an http message, checks whether the policy is violated
     * by checking if any of the registered rules is violated
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
