package org.zaproxy.zap.extension.policyloader.exceptions;

public class DuplicatePolicyException extends Exception {
    static final long serialVersionUID = 42L;

    public DuplicatePolicyException() {
        super("Duplicate policy");
    }
}
