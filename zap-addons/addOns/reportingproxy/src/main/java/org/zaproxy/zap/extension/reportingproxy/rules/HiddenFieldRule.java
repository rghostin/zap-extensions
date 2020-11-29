package org.zaproxy.zap.extension.reportingproxy.rules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.reportingproxy.Rule;
import org.zaproxy.zap.extension.reportingproxy.Violation;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// todo add tests
public class HiddenFieldRule implements Rule {

    Map<String,String> hiddenFields = new HashMap<>();

    private final Pattern INPUT_LINE =
            Pattern.compile("<\\s*input.*?>");
    private final Pattern HIDDEN_LINE =
            Pattern.compile("<\\s*input\\s+type=\\\"hidden\\\".*?>");
    private final Pattern NAME_HIDDEN_LINE =
            Pattern.compile("<\\s*input.*?name=\\\"(.*?)\\\".*?>");

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

            String outgoingHostname = msg.getRequestHeader().getHostName();
            if(!hiddenFields.containsKey(name)) {
                hiddenFields.put(name, outgoingHostname);
            } else {
                String domain = hiddenFields.get(name);
                if(!domain.equals(outgoingHostname)) {
                    return new Violation(getName(), getDescription(), msg, null);
                }
            }
        }
        return null;
    }
}
