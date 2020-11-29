/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.reportingproxy.rules;

import java.util.HashMap;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;

// todo add test class
public class RequestPerformanceRule implements Rule {

    // Threshold attributes
    int WEBSITE_THRESHOLD = 3;
    int TOTAL_THRESHOLD = 10;
    int COMPARISON_RATE = 2;
    public HashMap<String, Integer> siteElapsedTimeMap = new HashMap<String, Integer>();
    public HashMap<String, Integer> siteCounterMap = new HashMap<String, Integer>();

    /**
     * Returns the name of the rule
     *
     * @return
     */
    @Override
    public String getName() {
        return "Request performance rule";
    }

    /**
     * Returns the description of the rule
     *
     * @return
     */
    @Override
    public String getDescription() {
        return "The request performance for the site was significantly lower.";
    }

    /**
     * Adds the performance of the site to the performance map
     *
     * @return Returns the updated timestamps array list
     */
    private void performanceUpdate(HttpMessage msg) {
        String outgoingHostname = msg.getRequestHeader().getHostName();
        int new_elapsed_time = msg.getTimeElapsedMillis();
        if (siteElapsedTimeMap.containsKey(outgoingHostname)) {
            int old_elapse_avg = siteElapsedTimeMap.get(outgoingHostname);
            int count = siteCounterMap.get(outgoingHostname);
            int new_count = count + 1;
            int new_avg = (count * old_elapse_avg + new_elapsed_time) / new_count;
            siteElapsedTimeMap.put(outgoingHostname, new_avg);
            siteCounterMap.put(outgoingHostname, new_count);
        } else {
            siteElapsedTimeMap.put(outgoingHostname, new_elapsed_time);
            siteCounterMap.put(outgoingHostname, 1);
        }
    }
    /**
     * Returns the total number of requests recorded except the give the given domain
     *
     * @return Returns the updated timestamps array list
     */
    private int requestCounter(String domain) {
        int total_count = 0;
        for (String count_key : siteCounterMap.keySet()) {
            if (!domain.equals(count_key)) {
                total_count = total_count + siteCounterMap.get(count_key);
            }
        }
        return total_count;
    }

    /**
     * Calculates the average elapsed time except the provided domain
     *
     * @return Returns the updated timestamps array list
     */
    private int totalAvgElapsedTime(String domain) {
        int total_elapsed_time = 0;
        int total_count = 0;
        for (String count_key : siteCounterMap.keySet()) {
            if (!domain.equals(count_key)) {
                total_count = total_count + siteCounterMap.get(count_key);
                total_elapsed_time =
                        total_elapsed_time
                                + siteCounterMap.get(count_key) * siteElapsedTimeMap.get(count_key);
            }
        }
        return total_elapsed_time / total_count;
    }

    /**
     * Calculates the average elapsed time except the provided domain
     *
     * @return Returns the updated timestamps array list
     */
    private int domainAvgElapsedTime(String domain, int new_time) {
        int total_elapsed_time = new_time;
        int total_count = 1;
        for (String count_key : siteCounterMap.keySet()) {
            if (domain.equals(count_key)) {
                total_count = total_count + siteCounterMap.get(count_key);
                total_elapsed_time =
                        total_elapsed_time
                                + siteCounterMap.get(count_key) * siteElapsedTimeMap.get(count_key);
            }
        }
        return total_elapsed_time / total_count;
    }

    /**
     * Checks whether the HttpMessage violates the request performance rule or not
     *
     * @param msg the HttpMessage that will be checked
     * @return
     */
    @Override
    public Violation checkViolation(HttpMessage msg) {
        String outgoingHostname = msg.getRequestHeader().getHostName();
        if (siteCounterMap.containsKey(outgoingHostname)) {
            int new_elapsed_time = msg.getTimeElapsedMillis();
            int total_count = requestCounter(outgoingHostname);
            if (siteCounterMap.get(outgoingHostname) > WEBSITE_THRESHOLD - 1
                    && total_count > TOTAL_THRESHOLD - 1
                    && domainAvgElapsedTime(outgoingHostname, new_elapsed_time)
                            > totalAvgElapsedTime(outgoingHostname) * COMPARISON_RATE) {
                performanceUpdate(msg);
                return new Violation(getName(), getDescription(), msg, null);
            }
        }
        performanceUpdate(msg);
        return null;
    }
}
