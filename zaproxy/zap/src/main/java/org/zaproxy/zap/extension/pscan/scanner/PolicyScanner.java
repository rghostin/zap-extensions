package org.zaproxy.zap.extension.pscan.scanner;

import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.PolicyContainer;
import org.zaproxy.zap.extension.policyloader.PolicyNotFoundException;
import org.zaproxy.zap.extension.policyloader.Rule;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import java.util.List;

public class PolicyScanner extends PluginPassiveScanner {

    private PolicyContainer policies = new PolicyContainer();

    @Override
    public void setParent(PassiveScanThread parent) {
        // do nothing here
    }

    @Override
    public String getName() {
        return "Policy scanner";
    }

    private void raiseAlert(String policyName, String ruleName, HttpMessage msg) {
        String description = String.format("Policy_%s.Rule_%s violated", policyName, ruleName);
        newAlert().setName("Policy rule violation")
                .setDescription(description)
                .setMessage(msg)
                .setUri(msg.getRequestHeader().getURI().toString())
                .raise();
    }

    private void enforceOrRaise(Rule rule, String policyName, HttpMessage msg) {
        if (rule.isViolated(msg)) {
            raiseAlert(policyName, rule.getName(), msg);
        }
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // the work is done when the message is received
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        for (String policyName : policies.getPolicies()) {
            List<Rule> rules=null;
            try {
                rules = policies.getPolicyRules(policyName);
            } catch (PolicyNotFoundException e) {
                // wont happen
            }

            for (Rule rule : rules) {
                if (rule.isActiveForSend()) {
                    enforceOrRaise(rule, policyName, msg);
                }
                if (rule.isActiveForReceive()) {
                    enforceOrRaise(rule, policyName, msg);
                }
            }
        }
    }

}
