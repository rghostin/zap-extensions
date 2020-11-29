package org.zaproxy.zap.extension.reportingproxy.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.utils.Pair;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HiddenFieldRule implements Rule {

    // Map< (Name, Value), Domain>
    Map<Pair<String,String>,String> hiddenFields = new HashMap<>();
    // Map <(Name, Value), HttpMessage>
    Map<Pair<String, String>, HttpMessage> messageHistory = new HashMap<>();

    private final Pattern INPUT_LINE =
            Pattern.compile("<\\s*input.*?>");
    private final Pattern HIDDEN_LINE =
            Pattern.compile("<\\s*input\\s+type=\\\"hidden\\\".*?>");
    private final Pattern NAME_HIDDEN_LINE =
            Pattern.compile("<\\s*input.*?name=\\\"(.*?)\\\".*?>");
    private final Pattern NAME_HIDDEN_VALUE =
            Pattern.compile("<\\s*input.*?value=\\\"(.*?)\\\".*?>");

    @Override
    public String getName() {
        return "Hidden Field Rule";
    }

    @Override
    public String getDescription() {
        return "Check if Hidden Field ever sent to different domain";
    }


    @Override
    public Violation checkViolation(HttpMessage msg) {
        String httpResponseBody = msg.getResponseBody().toString();
        Matcher matcherInput = INPUT_LINE.matcher(httpResponseBody);

        while (matcherInput.find()) {
            String inputStr = matcherInput.group().trim();

            // if it is hidden
            Matcher matcherHidden = HIDDEN_LINE.matcher(inputStr);
            if(!matcherHidden.find()) continue;

            // get its name
            Matcher matcherName = NAME_HIDDEN_LINE.matcher(inputStr);
            String name = "";
            if(matcherName.matches()){
                name = matcherName.group(1);
            } else {
                continue;
            }

            Matcher matcherValue = NAME_HIDDEN_VALUE.matcher(inputStr);
            String value = "";
            if(matcherValue.matches()){
                value = matcherValue.group(1);
            }
            Pair<String,String> inputNameValuePair = new Pair<>(name,value);

            String outgoingHostname = msg.getRequestHeader().getHostName();
            if(!hiddenFields.containsKey(inputNameValuePair)) {
                hiddenFields.put(inputNameValuePair, outgoingHostname);
                messageHistory.put(inputNameValuePair, msg);
            } else {
                String domain = hiddenFields.get(inputNameValuePair);
                if(!domain.equals(outgoingHostname)) {
                    HttpMessage violatedMessage = messageHistory.get(inputNameValuePair);
                    return new Violation(getName(), getDescription(), msg, Arrays.asList(violatedMessage));
                }
            }
        }
        return null;
    }
}
