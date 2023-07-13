---
title: "Bypassing Amazon Waf to Pop an alert()"
date: 2022-08-29T21:34:30+05:30
draft: false
---

![](/images/img-bypassing-amazon-waf-to-pop-an-alert-0.png)

Hey everyone, its been a while since I published anything. This time, I’ll be sharing how I bypassed Amazon WAF to get XSS on the target. If you’re into bugbounty, it will help you in creating a mindset to create payloads that can bypass WAFs. Otherwise, it will be a good read. I promise!

For the unknown, a WAF (Web Application Firewall) is a firewall which is used to protect web applications from common attacks such as SQL injection, Cross-Site Scripting (XSS), etc., by filtering out malicious traffic.

# Discovery

During the content discovery phase, I was trying to gather as many endpoints as possible. Always do it with Burpsuite Proxy in the background with passive scanning extensions enabled. After spending a good amount of time I analyzed the sitemap that Burpsuite generated to inspect the endpoints manually. The target website itself was quite limited in functionality and therefore, I wasn’t able to find anything of use. Moving over to the robots.txt file, I saw a disallowed endpoint, namely `/index.aspx .`This was a bit strange because the website was running on Wordpress and pages with `.aspx` endpoints are not something that you’d see on a wordpress website.

The page itself was blank but on checking the source code, I saw some HTML and some javascript. This got me wondering what the purpose of this page is. I felt something was missing from the puzzle. Then I remembered that I can do some parameter discovery. Arjun ([https://github.com/s0md3v/Arjun](https://github.com/s0md3v/Arjun)) is a great tool for this purpose. It can query a huge list of parameter names with minimal requests to the server.

![](/images/img-bypassing-amazon-waf-to-pop-an-alert-1.png)

Using arjun to discover parameters

Out of the three parameters, the parameter `acc` is reflected on the webpage inside a `<script>`tag . The javascript looked like this:

```js
xt_multc ='&x1=0&x2=REFLECTION_POINT';
```

`REFLECTION_POINT` refers to the area where our parameter value is reflected. I need to escape the single quote to be able to inject javascript into the page.

I quickly ran `kxss` on the page with this parameter to identify special characters that are not sanitized/encoded and are reflected as is.

![](/images/img-bypassing-amazon-waf-to-pop-an-alert-2.png)

kxss is a great tool to identify unfiltered characters in parameters

As can be seen, there are a plenty of special characters that aren’t filtered, out of which, the single quote character is also one of them. This is good news since we are now one step closer to our goal.

At this point, I tried a simple payload such as `';alert(document.domain);//` . The WAF kicked in and the attempt failed.

![](/images/img-bypassing-amazon-waf-to-pop-an-alert-3.png)

Blocked ☠️

# Bypassing the WAF

Upon playing with different payloads, I came to a conclusion that payloads containing valid javascript function names such as `alert(` (yes, if there is an opening bracket after alert, it will get blocked. Without the opening bracket, it doesn’t get blocked) are blocked. I tried bypassing it by inserting a comment between the alert and the opening bracket and that too got blocked.

I tried fuzzing payloads based on this context (reflection inside Javascript string) with Burpsuite Intruder but it turned out to be unfruitful.

Fuzzing with functions other than `alert()`, I saw that some functions such as `fetch()` and `print()` are allowed. While, I could have used these to demonstrate the proof of concept in my report, I took it as a challenge to defeat the WAF and execute the `alert()` function.

Instead of writing `alert(document.domain)`, we can use the `window`object to call the `alert` function: `window["alert"](document.domain)` .

Unfortunately, this payload was also blocked. Then I remembered that I can use the multi-line comment syntax in Javascript in between the payload to fool the WAF which usually runs based on a set of rules and regular expressions.

The final payload is `';window/*aabb*/['al'%2b'ert'](document./*aabb*/location);//`. I split the “alert” string into two parts of “al” and “ert” and then added them. The plus symbol need to be URL encoded; otherwise it would be interpreted as the space symbol.

![](/images/img-bypassing-amazon-waf-to-pop-an-alert-4.png)

Popped an alert finally!

Hope you liked this blog. Thanks for reading and I’ll see you around :)

> Originally written on https://manash01.medium.com/bypassing-amazon-waf-to-pop-an-alert-4646ce35554e
