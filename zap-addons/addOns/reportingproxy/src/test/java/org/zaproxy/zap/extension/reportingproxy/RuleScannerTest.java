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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.exceptions.DuplicateRuleException;
import org.zaproxy.zap.extension.reportingproxy.exceptions.RuleNotFoundException;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

// todo fix
class RuleScannerTest {
        RuleScanner ruleScanner;

        @BeforeEach
        void setup() {
            ruleScanner = new RuleScanner();
        }

        @Test
        void getPluginId() {
            assertEquals(500001, ruleScanner.getPluginId());
        }

        @Test
        void getName() {
            assertEquals("Rule scanner", ruleScanner.getName());
        }

        private Rule getDummyRule(String name) {
            return new Rule() {
                @Override
                public String getName() {
                    return name;
                }

                @Override
                public String getDescription() {
                    return null;
                }

                @Override
                public Violation checkViolation(HttpMessage msg) {
                    return null;
                }
            };
        }

        @Test
        void addPolicy() {
            String name = "testRule";
            Rule rule = getDummyRule(name);

            try {
                ruleScanner.addRule(rule);
            } catch (DuplicateRuleException e) {
                fail("Should not have thrown exception");
            }
            assertThrows(
                    DuplicateRuleException.class,
                    () -> {
                        ruleScanner.addRule(rule);
                    });
        }

        @Test
        void removePolicy() {
            String name = "testPolicy";
            Rule rule = getDummyRule(name);

            try {
                ruleScanner.addRule(rule);
            } catch (DuplicateRuleException e) {
                fail("Should not have thrown exception");
            }

            try {
                ruleScanner.removeRule(name);
            } catch (RuleNotFoundException e) {
                fail("Should not have thrown exception");
            }

            assertThrows(
                    RuleNotFoundException.class,
                    () -> {
                        ruleScanner.removeRule("testPolicy");
                    });
        }

        @Test
        void scanHttpRequestSend() {
            // not active for now
        }

        @Test
        void scanHttpResponseReceive() {
            // not tested for now
        }
}
