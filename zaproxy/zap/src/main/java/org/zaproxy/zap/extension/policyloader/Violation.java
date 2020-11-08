package org.zaproxy.zap.extension.policyloader;

import org.parosproxy.paros.network.HttpMessage;

public class Violation {
    private String policyName;
    private String ruleName;
    private String description;
    private HttpMessage msg;

    public Violation(String policyName, Rule rule, HttpMessage msg) {
        this.policyName = policyName;
        this.ruleName = rule.getName();
        this.description = rule.getDescription();
        this.msg = msg;
    }

    public String getPolicyName() {
        return policyName;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getDescription() {
        return description;
    }

    public HttpMessage getMsg() {
        return msg;
    }

    public String getTitle() {
        return String.format("Policy_%s.Rule_%s violated", policyName, ruleName);
    }

    public String getUri() {
        return getMsg().getRequestHeader().getURI().toString();
    }



}
