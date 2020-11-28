package org.zaproxy.zap.extension.policyloader.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.policyloader.Rule;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ThresholdRule implements Rule {

    //Timestamp array for keeping records
    ArrayList<Integer> timestamps = new ArrayList<Integer>();

    @Override
    public String getName() {
        return "Threshold_rule";
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
        int second = 5;
        return second*1000;
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
        ArrayList<Integer> dummy_timestamps = timestamps;
        for (int timestmp : timestamps) {
            if ((current_time_int-timestmp) < getTimeThreshold()) {
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