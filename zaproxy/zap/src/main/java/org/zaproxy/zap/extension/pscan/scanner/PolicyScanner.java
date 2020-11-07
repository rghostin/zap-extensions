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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.PolicyContainer;
import org.zaproxy.zap.extension.policyloader.Rule;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;
import org.zaproxy.zap.extension.policyloader.exceptions.PolicyNotFoundException;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class PolicyScanner extends PluginPassiveScanner {

    private PolicyContainer policies = new PolicyContainer();

    @Override
    public int getPluginId() {
        return 500001;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // do nothing here
    }

    @Override
    public String getName() {
        return "Policy scanner";
    }

    private void raiseAlert(
            String policyName, String ruleName, String description, HttpMessage msg) {
        String title = String.format("Policy_%s.Rule_%s violated", policyName, ruleName);
        newAlert()
                .setName(title)
                .setDescription(description)
                .setMessage(msg)
                .setUri(msg.getRequestHeader().getURI().toString())
                .raise();
    }

    private void enforceOrRaise(Rule rule, String policyName, HttpMessage msg) {
        if (rule.isViolated(msg)) {
            raiseAlert(policyName, rule.getName(), rule.getDescription(), msg);
        }
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // the work is done when the message is received
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        for (String policyName : policies.getPolicies()) {
            Set<Rule> rules = null;
            try {
                rules = policies.getPolicyRules(policyName);
            } catch (PolicyNotFoundException e) {
                // wont happen
            }

            for (Rule rule : rules) {
                enforceOrRaise(rule, policyName, msg);
            }
        }
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String date =
                sdf.format(new Date(Long.parseLong(String.valueOf(System.currentTimeMillis()))));
    }

    public void addPolicy(String policyName, Set<Rule> rules) throws DuplicatePolicyException {
        policies.addPolicy(policyName, rules);
    }

    public void removePolicy(String policyName) throws PolicyNotFoundException {
        policies.removePolicy(policyName);
    }
}
