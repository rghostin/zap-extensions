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

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Rule;

public class ThresholdRule implements Rule {

    // Timestamp array for keeping records
    ArrayList<Integer> timestamps = new ArrayList<Integer>();

    @Override
    public String getName() {
        return "Threshold rule";
    }

    @Override
    public String getDescription() {
        return "The number of requests to the domain exceed the threshold.";
    }

    /**
     * Returns the provided domain
     *
     * @return Returns the domain string from a given list
     */
    private String getFlaggedDomain() {
        return "zerohedge.com";
    }

    /**
     * Returns the provided request threshold
     *
     * @return Returns the threshold number for request matches
     */
    private int getRequestThreshold() {
        return 5;
    }

    /**
     * Returns the provided time threshold in seconds as milliseconds
     *
     * @return Returns the time threshold in millisecond
     */
    private int getTimeThreshold() {
        int second = 1;
        return second * 1000;
    }

    /**
     * Returns the domain regex for the domain string provided
     *
     * @return Returns th domain' regex
     */
    private Pattern getRegexDomain() {
        String domain = getFlaggedDomain();
        Pattern domain_pattern =
                Pattern.compile("^(?:[a-z0-9]+[.])*" + domain + "$", Pattern.CASE_INSENSITIVE);
        return domain_pattern;
    }

    /**
     * Updates the timestamps array list for the timespan provided by the threshold
     *
     * @return Returns the updated timestamps array list
     */
    private ArrayList<Integer> updateTimestamps() {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        int current_time_int = (int) timestamp.getTime();
        ArrayList<Integer> dummy_timestamps = new ArrayList<Integer>();
        for (int timestmp : timestamps) {
            if ((current_time_int - timestmp) < getTimeThreshold()) {
                dummy_timestamps.add(timestmp);
            }
        }
        timestamps = dummy_timestamps;
        timestamps.add(current_time_int);
        return timestamps;
    }

    /**
     * Checks whether the HttpMessage violates the threshold rule or not
     *
     * @param msg the HttpMessage that will be checked
     * @return true if the HttpMessage violates the rule, false if not
     */
    @Override
    public boolean isViolated(HttpMessage msg) {
        String outgoingHostname = msg.getRequestHeader().getHostName();
        Pattern pattern = getRegexDomain();
        Matcher matcher = pattern.matcher(outgoingHostname);
        if (matcher.matches()) {
            timestamps = updateTimestamps();
            if (timestamps.size() > getRequestThreshold()) {
                return true;
            }
            return false;
        }
        return false;
    }
}
