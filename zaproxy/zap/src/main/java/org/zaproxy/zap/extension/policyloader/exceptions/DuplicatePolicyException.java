package org.zaproxy.zap.extension.policyloader.exceptions;

public class DuplicatePolicyException extends Exception {
    public DuplicatePolicyException() {
        super("Duplicate policy");
    }
}
