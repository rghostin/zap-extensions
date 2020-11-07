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
import org.zaproxy.zap.extension.policyloader.Rule;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;

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

        try {
            policyScanner.addPolicy("testPolicy", rules);
        } catch (DuplicatePolicyException e) {
            fail("Should not have thrown exception");
        }
        assertThrows(
                DuplicatePolicyException.class,
                () -> {
                    policyScanner.addPolicy("testPolicy", rules);
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

    // todo test remove policy
}
