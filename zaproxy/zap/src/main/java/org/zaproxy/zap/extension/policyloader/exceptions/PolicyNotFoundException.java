package org.zaproxy.zap.extension.policyloader.exceptions;

public class PolicyNotFoundException extends Exception {
    static final long serialVersionUID = 42L;

    public PolicyNotFoundException() {
        super("Policy not found");
    }
}
