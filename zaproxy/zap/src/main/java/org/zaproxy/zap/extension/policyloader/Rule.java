package org.zaproxy.zap.extension.policyloader;

import org.parosproxy.paros.network.HttpMessage;

/**
 * This is public interface for runtime rule inspection
 */
public interface Rule {

    /**
     * Returns this rule's name
     * @return Returns this rule's name
     */
    String getName();

    /**
     * Returns this rule's description
     * @return Returns this rule's description
     */
    String getDescription();

    /**
     * Checks whether the HttpMessage violates a specific rule
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    boolean isViolated(HttpMessage msg);
}
