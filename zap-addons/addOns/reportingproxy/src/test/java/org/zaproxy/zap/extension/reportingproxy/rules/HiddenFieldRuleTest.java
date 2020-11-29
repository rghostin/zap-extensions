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

import java.util.*;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Violation;

class HiddenFieldRuleTest {

    private List<String> getURLStringsCorrect() {
        return new ArrayList<>(
                Arrays.asList(
                        "http://google.com",
                        "http://zerohedge.com",
                        "http://youtube.com",
                        "http://imdb.com",
                        "http://cern.ch"));
    }

    private List<String> getURLStringsWrong() {
        return new ArrayList<>(
                Arrays.asList(
                        "http://google2.com",
                        "http://zerohedge2.com",
                        "http://youtube2.com",
                        "http://imdb2.com",
                        "http://cern.ch"));
    }

    private HttpMessage createHttpMsg(String url)
            throws URIException, HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage(new URI(url, true));
        return msg;
    }

    @Test
    void getName() {
        HiddenFieldRule hiddenFieldRule = new HiddenFieldRule();
        assertEquals("Hidden Field Rule", hiddenFieldRule.getName());
    }

    @Test
    void getDescription() {
        HiddenFieldRule hiddenFieldRule = new HiddenFieldRule();
        assertEquals(
                "Check if Hidden Field ever sent to different domain",
                hiddenFieldRule.getDescription());
    }

    @Test
    void checkViolation() throws HttpMalformedHeaderException, URIException {
        String responseBody = "<input type=\"hidden\" name=\"test\" value=\"babble\">";
        String responseBody2 = "<input type=\"hidden\" id=\"123\" name=\"tes2t\" value=\"babble\">";

        List<String> url_correct = getURLStringsCorrect();
        List<String> url_correct2 = getURLStringsCorrect();
        List<String> url_wrong = getURLStringsWrong();

        Iterator<String> uc = url_correct.iterator();
        Iterator<String> uc2 = url_correct2.iterator();
        Iterator<String> uw = url_wrong.iterator();

        while (uc.hasNext() && uc2.hasNext() && uw.hasNext()) {
            // each time get a empty rule to check
            HiddenFieldRule hiddenFieldRule = new HiddenFieldRule();

            HttpMessage httpMessageCorrect = createHttpMsg(uc.next());
            httpMessageCorrect.setResponseBody(responseBody);

            HttpMessage httpMessageCorrect2 = createHttpMsg(uc2.next());
            httpMessageCorrect2.setResponseBody(responseBody2);

            HttpMessage httpMessageWrong = createHttpMsg(uw.next());
            httpMessageWrong.setResponseBody(responseBody);

            // serial assertion
            assertNull(hiddenFieldRule.checkViolation(httpMessageCorrect));
            assertNull(hiddenFieldRule.checkViolation(httpMessageCorrect2));

            Violation v = hiddenFieldRule.checkViolation(httpMessageWrong);
            assertEquals(hiddenFieldRule.getName(), v.getRuleName());
            assertEquals(hiddenFieldRule.getDescription(), v.getDescription());
            assertEquals(
                    httpMessageWrong.getRequestHeader().getURI().toString(), v.getTriggeringUri());
        }
    }
}
