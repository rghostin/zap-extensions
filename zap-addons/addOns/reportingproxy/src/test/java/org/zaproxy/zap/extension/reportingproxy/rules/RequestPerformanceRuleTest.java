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

// todo fix
class RequestPerformanceRuleTest {

    //    RequestPerformanceRule requestRule;
    //
    //    @BeforeEach
    //    void setup() {
    //        requestRule = new RequestPerformanceRule();
    //    }
    //
    //    static HttpMessage createHttpMsg(String url) throws URIException,
    // HttpMalformedHeaderException {
    //        HttpMessage msg = new HttpMessage(new URI(url, true));
    //        return msg;
    //    }
    //
    //    private HashMap<String, Integer> getTestElapsedTimeMap() {
    //        HashMap<String, Integer> testSiteElapsedTimeMap = new HashMap<String, Integer>();
    //        testSiteElapsedTimeMap.put("cern.ch", 1000);
    //        testSiteElapsedTimeMap.put("facebook.com", 1000);
    //        testSiteElapsedTimeMap.put("zerohedge.com", 3000);
    //        return testSiteElapsedTimeMap;
    //    }
    //
    //    private HashMap<String, Integer> getTestCounterMap() {
    //        HashMap<String, Integer> testCounterMap = new HashMap<String, Integer>();
    //        testCounterMap.put("cern.ch", 5);
    //        testCounterMap.put("facebook.com", 6);
    //        testCounterMap.put("zerohedge.com", 3);
    //        return testCounterMap;
    //    }
    //
    //    @Test
    //    void getName() {
    //        assertEquals("Request performance rule", requestRule.getName());
    //    }
    //
    //    @Test
    //    void getDescription() {
    //        assertEquals(
    //                "The request performance for the site was significantly lower.",
    //                requestRule.getDescription());
    //    }
    //
    //    // HIGH number of requests, HIGH number of domain specific request and LOW performance
    //    @Test
    //    void isViolatedHighHighLow() throws HttpMalformedHeaderException, URIException {
    //        HttpMessage msg = new HttpMessage(new URI("http://zerohedge.com/", true));
    //        msg.setTimeElapsedMillis(5000);
    //        requestRule.siteCounterMap = getTestCounterMap();
    //        requestRule.siteElapsedTimeMap = getTestElapsedTimeMap();
    //        assertTrue(requestRule.isViolated(msg));
    //    }
    //
    //    // LOW number of requests, HIGH number of domain specific request and LOW performance
    //    @Test
    //    void isViolatedLowHighLow() throws HttpMalformedHeaderException, URIException {
    //        HttpMessage msg = new HttpMessage(new URI("http://zerohedge.com/", true));
    //        msg.setTimeElapsedMillis(5000);
    //        HashMap<String, Integer> test_map_req = getTestCounterMap();
    //        test_map_req.remove("cern.ch");
    //        HashMap<String, Integer> test_map_time = getTestElapsedTimeMap();
    //        test_map_time.remove("cern.ch");
    //        requestRule.siteCounterMap = test_map_req;
    //        requestRule.siteElapsedTimeMap = test_map_time;
    //        assertFalse(requestRule.isViolated(msg));
    //    }
    //
    //    // HIGH number of requests, LOW number of domain specific request and LOW performance
    //    @Test
    //    void isViolatedHighLowLow() throws HttpMalformedHeaderException, URIException {
    //        HttpMessage msg = new HttpMessage(new URI("http://zerohedge.com/", true));
    //        msg.setTimeElapsedMillis(5000);
    //        HashMap<String, Integer> test_map_req = getTestCounterMap();
    //        test_map_req.remove("zerohedge.com");
    //        HashMap<String, Integer> test_map_time = getTestElapsedTimeMap();
    //        test_map_time.remove("zerohedge.com");
    //        requestRule.siteCounterMap = test_map_req;
    //        requestRule.siteElapsedTimeMap = test_map_time;
    //        assertFalse(requestRule.isViolated(msg));
    //    }
    //
    //    // LOW number of requests, LOW number of domain specific request and HIGH performance
    //    @Test
    //    void isViolatedLowLowHigh() throws HttpMalformedHeaderException, URIException {
    //        HttpMessage msg = new HttpMessage(new URI("http://zerohedge.com/", true));
    //        msg.setTimeElapsedMillis(1000);
    //        HashMap<String, Integer> test_map_time = getTestElapsedTimeMap();
    //        test_map_time.replace("zerohedge.com", 1000);
    //        requestRule.siteCounterMap = getTestCounterMap();
    //        requestRule.siteElapsedTimeMap = test_map_time;
    //        assertFalse(requestRule.isViolated(msg));
    //    }
}
