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

import static org.junit.jupiter.api.Assertions.*;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Violation;

class ThresholdRuleTest {

    ThresholdRule thresholdRule;

    @BeforeEach
    void setup() {
        thresholdRule = new ThresholdRule();
    }

    private static HttpMessage createHttpMsg(String url)
            throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI(url, true));
        return msg;
    }

    private String getFlaggedURL() {
        return "www.zerohedge.com";
    }

    private String getNotFlaggedURL() {
        return "www.cern.ch";
    }

    private ArrayList<Integer> getTimestampArrayExceed() {
        ArrayList<Integer> timestamps = new ArrayList<Integer>();
        int count = 0;
        while (count < 5) {
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            int test_time_int = (int) timestamp.getTime();
            timestamps.add(test_time_int);
            count++;
        }
        return timestamps;
    }

    private ArrayList<Integer> getTimestampArrayNotExceed() {
        ArrayList<Integer> timestamps = new ArrayList<Integer>();
        int count = 0;
        while (count < 1) {
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            int test_time_int = (int) timestamp.getTime();
            timestamps.add(test_time_int);
            count++;
        }
        return timestamps;
    }

    private List<HttpMessage> getHttpMessagesExceed(HttpMessage msg) {
        List<HttpMessage> messages = new ArrayList<HttpMessage>();
        int count = 0;
        while (count < 5) {
            messages.add(msg);
            count++;
        }
        return messages;
    }

    private List<HttpMessage> getHttpMessagesNotExceed(HttpMessage msg) {
        List<HttpMessage> messages = new ArrayList<HttpMessage>();
        int count = 0;
        while (count < 1) {
            messages.add(msg);
            count++;
        }
        return messages;
    }

    private boolean assertViolation(Violation v1, Violation v2) {
        if (v1.getRuleName().equals(v2.getRuleName())
                && v1.getDescription().equals(v2.getDescription())
                && v1.getEvidenceMessages().equals(v2.getEvidenceMessages())
                && (v1.getTriggeringMsg() == v2.getTriggeringMsg())) {
            return true;
        }
        return false;
    }

    @Test
    void getName() {
        assertEquals("Threshold rule", thresholdRule.getName());
    }

    @Test
    void getDescription() {
        assertEquals(
                "The number of requests to the domain exceed the threshold.",
                thresholdRule.getDescription());
    }

    // checks for the case in which the flagged domain is detected it exceeds request
    // threshold
    @Test
    void isViolatedMatchTrue() throws HttpMalformedHeaderException, URIException {
        String url = getFlaggedURL();
        HttpMessage msg = ThresholdRuleTest.createHttpMsg(url);
        thresholdRule.timestamps = getTimestampArrayExceed();
        thresholdRule.messages = getHttpMessagesExceed(msg);
        Violation vio = thresholdRule.checkViolation(msg);
        List<HttpMessage> messages = thresholdRule.messages;
        messages.add(msg);
        Violation violation =
                new Violation(
                        thresholdRule.getName(), thresholdRule.getDescription(), msg, messages);
        assertViolation(vio, violation);
    }

    // checks for the case in which the flagged domain is detected it does not exceed request
    // threshold
    @Test
    void isViolatedMatchFalse() throws HttpMalformedHeaderException, URIException {
        String url = getFlaggedURL();
        HttpMessage msg = ThresholdRuleTest.createHttpMsg(url);
        thresholdRule.timestamps = getTimestampArrayNotExceed();
        thresholdRule.messages = getHttpMessagesNotExceed(msg);
        assertNull(thresholdRule.checkViolation(msg));
    }

    // checks for the case in which the flagged domain is not detected and it exceeds request
    // threshold
    @Test
    void isViolatedNoMatchExceed() throws HttpMalformedHeaderException, URIException {
        String url = getNotFlaggedURL();
        HttpMessage msg = ThresholdRuleTest.createHttpMsg(url);
        thresholdRule.messages = getHttpMessagesExceed(msg);
        thresholdRule.timestamps = getTimestampArrayExceed();
        assertNull(thresholdRule.checkViolation(msg));
    }

    // checks for the case in which the flagged domain is not detected and it does not exceed
    // request threshold
    @Test
    void isViolatedNoMatchNotExceed() throws HttpMalformedHeaderException, URIException {
        String url = getNotFlaggedURL();
        HttpMessage msg = ThresholdRuleTest.createHttpMsg(url);
        thresholdRule.timestamps = getTimestampArrayNotExceed();
        thresholdRule.messages = getHttpMessagesNotExceed(msg);
        assertNull(thresholdRule.checkViolation(msg));
    }
}
