package org.zaproxy.zap.extension.policyloader.exceptions;

/**
 * This is an exception that is thrown when a policy is not found
 */
public class PolicyNotFoundException extends Exception {

    static final long serialVersionUID = 42L;

    /**
     * Constructs a new exception with null as its detail message
     */
    public PolicyNotFoundException() {
        super("Policy not found");
    }
}
