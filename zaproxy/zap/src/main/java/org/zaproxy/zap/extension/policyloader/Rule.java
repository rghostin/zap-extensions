package org.zaproxy.zap.extension.policyloader;

import org.parosproxy.paros.network.HttpMessage;

public interface Rule {
    String getName();
    String getDescription();
    boolean isViolated(HttpMessage msg);
}
