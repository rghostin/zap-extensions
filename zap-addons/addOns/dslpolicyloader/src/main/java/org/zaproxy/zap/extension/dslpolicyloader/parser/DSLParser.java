package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.dslpolicyloader.Policy;
import org.zaproxy.zap.extension.dslpolicyloader.Rule;

import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// todo test

/**
 * Parses a policy declaration as defined in the DSL
 */
public class DSLParser {
    private static final String RE_RULE_DECLARATION = "^rule\\s+\"(.+?)\"\\s+\"(.+?)\"\\s*:\\s*(.+)$";
    private static final Pattern PATTERN_RULE_DECLARATION = Pattern.compile(RE_RULE_DECLARATION);

    // todo test

    /**
     * Parses a rule declaration as defined in the DSL
     * @param ruleDsl : the rule declaration
     * @return : A rule object representing the rule declaration
     */
    private Rule parseRule(String ruleDsl){
        Matcher ruleMatcher = PATTERN_RULE_DECLARATION.matcher(ruleDsl);
        boolean matches = ruleMatcher.matches();
        assert matches;
        String name = ruleMatcher.group(1);
        String description = ruleMatcher.group(2);
        String composeodStatement = ruleMatcher.group(3);

        Predicate<HttpMessage> predicate = new StatementParser(composeodStatement).parse();
        return new Rule(name, description, predicate);
    }

    Policy parsePolicy(String policyContent) {
        String dummy_name = "Dummy Policy Name";
        Policy policy = new Policy(dummy_name);
        String[] splitted_policy = policyContent.split(";");
        for (String str_rule: splitted_policy) {
            Rule rule = parseRule(str_rule);
            policy.addRule(rule);
        }
        return policy;
    }

}
