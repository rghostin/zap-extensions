package org.zaproxy.zap.extension.policyloader;

import org.parosproxy.paros.network.HttpMessage;

public interface Rule {
    String getName();
    boolean isActiveForSend();
    boolean isActiveForReceive();
    boolean isViolated(HttpMessage msg);
}
