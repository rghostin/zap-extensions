package org.zaproxy.zap.extension.reportingproxy.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Pair;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HiddenFieldRule implements Rule {

    // Map< (Name, Value), Domain>
    Map<Pair<String,String>,String> hiddenFields = new HashMap<>();
    List<HttpMessage> HTTP_MESSAGE_HIDDEN_INPUT = new ArrayList<>();

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
            Pair<String,String> p = new Pair<>(name,value);

            String outgoingHostname = msg.getRequestHeader().getHostName();
            if(!hiddenFields.containsKey(p)) {
                hiddenFields.put(p, outgoingHostname);
            } else {
                String domain = hiddenFields.get(p);
                if(!domain.equals(outgoingHostname)) {
                    HTTP_MESSAGE_HIDDEN_INPUT.add(msg);
                    return new Violation(getName(), getDescription(), msg, HTTP_MESSAGE_HIDDEN_INPUT);
                }
            }
        }
        return null;
    }

    public String test(){
        return hiddenFields.keySet().toString();
    }
}
