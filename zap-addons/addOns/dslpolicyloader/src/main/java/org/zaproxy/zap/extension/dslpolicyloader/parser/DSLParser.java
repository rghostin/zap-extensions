package org.zaproxy.zap.extension.dslpolicyloader.parser;

import org.zaproxy.zap.extension.dslpolicyloader.Policy;
import org.zaproxy.zap.extension.dslpolicyloader.Rule;

public class DSLParser {


    Rule parseRule(String ruleDsl){
        //re = "rule\s+"(.+?)"\s+"(.+?)"\s*:";
        //parse on ; and delegate to sttmt parser
        return null;
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

    //TODO REMOVE THIS
    public static void main(String[] args) {
        String policyContent =
                "Rule \"<name>\" \"<description>\":\n" +
                "request.header.re=\"abc\" and not ( response.header.value=\"def\" or response.body.values=[\"x\",\"y\",\"z\"] ) ;\n" +
                "\n" +
                "Rule \"<name>\" \"<description>\":\n" +
                "request.header.re=\"abc\" and ( response.header.value=\"def\" or response.body.values=[\"x\",\"y\",\"z\"] ) ;\n;";
        String[] splitted_policy = policyContent.split(";");
        for (String str_rule: splitted_policy) {
            System.out.println(str_rule);
        }
    }
}
