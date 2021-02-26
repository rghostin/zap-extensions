# README

## Description
ZAP custom extensions consists of a set of addons to the OWASP ZAP Zed Attack Proxy.

The project is part of the course "Design of Software Systems" at KU Leuven.

Score: 20/20.

This is a mirror repository, credit goes to my colleagues:
- Deniz Alp Savaskan
- Tianjian Song
- Xinhai Zhou


## The extensions
- Passive scanner that generate alerts on various channels (UI,HTML report) when a violation is detected. The scanning happens per request so only stateless violations are supported. Some violations we implemented:

      - Request that are not under HTTPs are flagged
      - Requests containing cookies without Secure; http_only;Samesite flags are flagged.
      - Bodies containing email addresses are flagged.
      - Requests going to a some blacklisted domains are flagged.
      - HTTPs responses that don't include HSTS are flagged.
      
The addon also includes a mechanism for users to implement custom violations easily and load them into ZAP.


- Designed a simple declarative Domain Spefic language (DSL) that greatly improve the usability(ISO25010) of specifying violations as predicates. The DSL is inspired from the Wireshark's filtering language. Example:
```
Rule "RULE_TITLE" "RULE_DESCRIPTION":
response.body.values=["X","Y", "Z"] and not request.header.re="^AB.*c[0-9]"

Rule "ANOTHER_RULE" "ANOTHER_DESCRIPTION":
request.header.value="ABC" or request.header.re="^AB.*c[0-9]"
```

- Passive scanner that generates alerts on various channels (UI, HTML report) when a violation is detected. Violations are stateful and can span over multiple requests.

Some of violations we implemented:

- Detect the number if the number of requests to a certain domain in a  certain timespan exceeds a preset threshold. This rule can be used to warn about hitting API rate limits.
- Detect the common reponse headers present in the 5 previous requests from the origin and are absent in the current request. Example HSTS.
- Detect forms that are submitted to a domain different from their origin.
- Detect if a website is on average 10x slower than other visited websites in the same session.
