package org.zaproxy.zap.extension.policyloader;

public class PolicyNotFoundException extends Exception {
    PolicyNotFoundException() {
        super("Policy not found");
    }
}
