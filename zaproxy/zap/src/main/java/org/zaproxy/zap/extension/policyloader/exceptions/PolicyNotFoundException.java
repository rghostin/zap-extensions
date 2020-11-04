package org.zaproxy.zap.extension.policyloader.exceptions;

public class PolicyNotFoundException extends Exception {
    public PolicyNotFoundException() {
        super("Policy not found");
    }
}
