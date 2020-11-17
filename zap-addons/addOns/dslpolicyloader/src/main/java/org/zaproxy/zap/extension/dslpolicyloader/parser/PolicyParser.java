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
package org.zaproxy.zap.extension.dslpolicyloader.parser;

import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.Policy;
import org.zaproxy.zap.extension.dslpolicyloader.Rule;
import org.zaproxy.zap.extension.dslpolicyloader.exceptions.SyntaxErrorException;

// todo test

/** Parses a policy declaration as defined in the DSL */
public class PolicyParser {
    private static final String RE_RULE_DECLARATION =
            "^Rule\\s+\"(.+?)\"\\s+\"(.+?)\"\\s*:\\s*(.+)$";
    private static final Pattern PATTERN_RULE_DECLARATION = Pattern.compile(RE_RULE_DECLARATION);

    // todo test

    /**
     * Parses a rule declaration as defined in the DSL
     *
     * @param ruleDsl : the rule declaration
     * @return : A rule object representing the rule declaration
     */
    private Rule parseRule(String ruleDsl) throws SyntaxErrorException {
        Matcher ruleMatcher = PATTERN_RULE_DECLARATION.matcher(ruleDsl);
        boolean matches = ruleMatcher.matches();
        assert matches;
        String name = ruleMatcher.group(1);
        String description = ruleMatcher.group(2);
        String composeodStatement = ruleMatcher.group(3);

        Predicate<HttpMessage> predicate = new StatementParser(composeodStatement).parse();
        return new Rule(name, description, predicate);
    }

    /**
     * Parses a policy declaration as defined in the DSL
     *
     * @param policyContent : the policy declaration
     * @param name : the policy name
     * @return : A policy object representing the policy declaration
     */
    public Policy parsePolicy(String policyContent, String name) throws SyntaxErrorException {
        Policy policy = new Policy(name);
        String[] splitted_policy = policyContent.trim().split(";");
        for (String str_rule : splitted_policy) {
            str_rule = str_rule.trim();
            Rule rule = parseRule(str_rule);
            policy.addRule(rule);
        }
        return policy;
    }
}
