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

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import java.sql.Timestamp;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

// todo fix
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
        //threshold
        @Test
        void isViolatedMatchTrue() throws HttpMalformedHeaderException, URIException {
            String url = getFlaggedURL();
            thresholdRule.timestamps = getTimestampArrayExceed();
            HttpMessage msg = ThresholdRuleTest.createHttpMsg(url);
            assertTrue(thresholdRule.isViolated(msg));
        }

        // checks for the case in which the flagged domain is detected it does not request
        //threshold
        @Test
        void isViolatedMatchFalse() throws HttpMalformedHeaderException, URIException {
            String url = getFlaggedURL();
            thresholdRule.timestamps = getTimestampArrayNotExceed();
            HttpMessage msg = ThresholdRuleTest.createHttpMsg(url);
            System.out.println(thresholdRule.timestamps);
            assertFalse(thresholdRule.isViolated(msg));
        }

        // checks for the case in which the flagged domain is not detected and it exceeds request
        // threshold
        @Test
        void isViolatedNoMatchExceed() throws HttpMalformedHeaderException, URIException {
            String url = getNotFlaggedURL();
            thresholdRule.timestamps = getTimestampArrayExceed();
            HttpMessage msg = ThresholdRuleTest.createHttpMsg(url);
            assertFalse(thresholdRule.isViolated(msg));
        }

        // checks for the case in which the flagged domain is not detected and it does not exceed
        // request threshold
        @Test
        void isViolatedNoMatchNotExceed() throws HttpMalformedHeaderException, URIException {
            String url = getNotFlaggedURL();
            thresholdRule.timestamps = getTimestampArrayNotExceed();
            HttpMessage msg = ThresholdRuleTest.createHttpMsg(url);
            assertFalse(thresholdRule.isViolated(msg));
        }
}
