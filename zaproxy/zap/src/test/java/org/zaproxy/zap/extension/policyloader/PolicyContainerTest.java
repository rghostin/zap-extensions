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

// TODO test

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.policyloader.exceptions.PolicyNotFoundException;
import org.zaproxy.zap.extension.policyloader.rules.*;

import java.security.Policy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

class PolicyContainerTest {

    private Map<String, Set<Rule>> existPolicy = new HashMap<>();
    private Map<String, Set<Rule>> addPolicy = new HashMap<>();
    PolicyContainer policies = new PolicyContainer();

    @BeforeEach
    void setPolicies() {
        String existPolicyName = "existPolicy";
        Set<Rule> existPolicyRules = new HashSet<>();
        existPolicyRules.add(new KeywordMatchingRule());
        existPolicyRules.add(new HSTSRule());
        existPolicyRules.add(new EmailMatchingRule());
        existPolicyRules.add(new HTTPSRule());
        existPolicy.put(existPolicyName, existPolicyRules);

        String addPolicyName = "addPolicy";
        Set<Rule> addPolicyRules = new HashSet<>();
        addPolicyRules.add(new KeywordMatchingRule());
        addPolicyRules.add(new HSTSRule());
        addPolicyRules.add(new EmailMatchingRule());
        addPolicyRules.add(new HTTPSRule());
        addPolicyRules.add(new DomainMatchingRule());
        addPolicyRules.add(new ExpectCTRule());
        addPolicyRules.add(new CookieAttrRule());
        addPolicy.put(addPolicyName, addPolicyRules);

        try {
            policies.addPolicy(existPolicyName, existPolicyRules);
        } catch (DuplicatePolicyException e) {
            fail("Should not have thrown DuplicatePolicyException");
            e.printStackTrace();
        }

    }

    @Test
    void addPolicy() {
        try {
            policies.addPolicy("addpolicy", addPolicy.get(addPolicy));
        } catch (DuplicatePolicyException e) {
            fail("Should not have thrown DuplicatePolicyException");
            e.printStackTrace();
        }

        Set<String> policies = this.policies.getPolicies();
        if (policies.contains("addpolicy")) {
            assertTrue(true);
        } else {
            assertTrue(false);
        }
    }

    @Test
    void removePolicy() {
        try {
            policies.removePolicy("existPolicy");
        } catch (PolicyNotFoundException e) {
            fail("Should not have thrown PolicyNotFoundException");
            e.printStackTrace();
        }

        Set<String> policies = this.policies.getPolicies();
        if (policies.contains("existPolicy")) {
            assertTrue(false);
        } else {
            assertTrue(true);
        }
    }

    @Test
    void getPolicyRules() {
        Set<String> targetPolicyRulesName = new HashSet<>();
        targetPolicyRulesName.add(new KeywordMatchingRule().getName());
        targetPolicyRulesName.add(new HSTSRule().getName());
        targetPolicyRulesName.add(new EmailMatchingRule().getName());
        targetPolicyRulesName.add(new HTTPSRule().getName());
        Set<Rule> policyRules;

        try {
            policyRules = policies.getPolicyRules("existPolicy");
            System.out.println(policyRules);
            System.out.println(targetPolicyRulesName);
            assertTrue(equal(targetPolicyRulesName, policyRules));

        } catch (PolicyNotFoundException e) {
            fail("Should not have thrown PolicyNotFoundException");
            e.printStackTrace();
        }

    }

    @Test
    void getPolicies() {
        Set<String> policies = this.policies.getPolicies();
        if (policies.contains("existPolicy")) {
            assertTrue(true);
        } else {
            assertTrue(false);
        }
    }

    private boolean equal(Set<String> targetRulesName, Set<Rule> checkRules) {
        if(checkRules ==null){
            return false;
        }
        Set<String> targetRulesNameCompare = new HashSet<>();
        targetRulesNameCompare.addAll(targetRulesName);
        for (Rule checkRulesElem : checkRules) {
            if (targetRulesNameCompare.contains(checkRulesElem.getName())) {
                targetRulesNameCompare.remove(checkRulesElem.getName());
            }
        }
        if (targetRulesNameCompare.size() == 0) {
            return true;
        } else {
            return false;
        }
    }
}
