package org.zaproxy.zap.extension.policyloader;

public class DuplicatePolicyException extends Exception {
    DuplicatePolicyException() {
        super("Duplicate policy");
    }
}
