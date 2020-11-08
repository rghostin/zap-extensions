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
package org.zaproxy.zap.extension.pscan.scanner;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.policyloader.Policy;
import org.zaproxy.zap.extension.policyloader.Rule;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.policyloader.exceptions.PolicyNotFoundException;

class PolicyScannerTest {
    PolicyScanner policyScanner;

    @BeforeEach
    void setup() {
        policyScanner = new PolicyScanner();
    }

    @Test
    void getPluginId() {
        assertEquals(500001, policyScanner.getPluginId());
    }

    @Test
    void getName() {
        assertEquals("Policy scanner", policyScanner.getName());
    }

    @Test
    void addPolicy() {
        String policyName = "testPolicy";
        Set<Rule> rules = new HashSet<>();
        Policy policy = new Policy(policyName);


        try {
            policyScanner.addPolicy(policy);
        } catch (DuplicatePolicyException e) {
            fail("Should not have thrown exception");
        }
        assertThrows(
                DuplicatePolicyException.class,
                () -> {
                    policyScanner.addPolicy(policy);
                });
    }

    @Test
    void removePolicy() {
        String policyName = "testPolicy";
        Set<Rule> rules = new HashSet<>();
        Policy policy = new Policy(policyName);

        try {
            policyScanner.addPolicy(policy);
        } catch (DuplicatePolicyException e) {
            fail("Should not have thrown exception");
        }

        try {
            policyScanner.removePolicy(policyName);
        } catch (PolicyNotFoundException e) {
            fail("Should not have thrown exception");
        }

        assertThrows(
                PolicyNotFoundException.class,
                () -> {
                    policyScanner.removePolicy("testPolicy");
                });
    }

    @Test
    void scanHttpRequestSend() {
        // not active for now
    }

    @Test
    void scanHttpResponseReceive() {
        // todo test
    }
}
