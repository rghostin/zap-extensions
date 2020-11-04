package org.zaproxy.zap.extension.policyloader;

import java.util.*;

public class PolicyContainer {
    private Map<String, List<Rule>> policies = new HashMap<>();

    private boolean policyExists(String policyName) {
        return policies.containsKey(policyName);
    }

    public void addPolicy(String policyName, List<Rule> rules) throws DuplicatePolicyException {
        if (policyExists(policyName)) {
            throw new DuplicatePolicyException();
        }
        policies.put(policyName, rules);
    }

    public void removePolicy(String policyName) throws PolicyNotFoundException {
        if (! policyExists(policyName)) {
            throw new PolicyNotFoundException();
        }
        policies.remove(policyName);
    }

    public List<Rule> getPolicyRules(String policyName) throws PolicyNotFoundException {
        if (! policyExists(policyName)) {
            throw new PolicyNotFoundException();
        }
        return policies.get(policyName);
    }

    public Set<String> getPolicies() {
        return policies.keySet();
    }
}


