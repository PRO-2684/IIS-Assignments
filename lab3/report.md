# Lab3

## 1

> **Same Origin Policy**
>
> We discussed in lecture how the DOM same-origin policy defines an origin as the triple (protocol, domain, port). Explain what would go wrong if the DOM same-origin policy were only defined by domain, and nothing else. Give a concrete example of an attack that a network attacker can do in this case, but cannot do when using the standard definition of the same-origin policy.

## 2

> Two new extensions to DNS have been recently ratified by the Internet standards community: DNS-over-HTTPS and DNS-over-TLS. The protocols work similarly to DNS except that DNS queries are sent over a standard encrypted HTTPS or TLS tunnel.
>
> a) What is one DNS attack that DNS-over-HTTPS protects against?
> b) What is one DNS attack that DNS-over-HTTPS does not protect against?
> c) Do DoH or DoT prevent DNS from being used as a DDoS amplifier? Why or why not?
> d) Do DoH or DoT protect against DNS rebinding attacks? Why or why not?

## 3

> **Cross Site Script Inclusion (XSSI) Attacks**
>
> Consider a banking web site bank.com where after login the user is taken to a user information page: `https://bank.com/accountInfo.html`
>
> The page shows the user's account balances. Here accountInfo.html is a static page: it contains the page layout, but no user data. Towards the bottom of the page a script is included as:
>
> ```html
> <script src="//bank.com/userdata.js"></script> (\*)
> ```
>
> The contents of `userdata.js` is as follows:
>
> ```javascript
> displayData({
>     "name": "John Doe",
>     "AccountNumber": 12345,
>     "Balance": 45
> })
> ```
>
> The function `displayData` is defined in `accountInfo.html` and uses the provided data to populate the page with user data.
>
> The script `userdata.js` is generated dynamically and is the only part of the page that contains user data. Everything else is static content.
>
> Suppose that after the user logs in to his or her account at bank.com the site stores the user's session token in a browser cookie.
>
> a) Consider user John Doe who logs into his account at `bank.com` and then visits the URL `https://evil.com/`. Explain how the page at `evil.com` can cause all of John Doe's data to be sent to `evil.com`. Please provide the code contained in the page at `evil.com`. The code can be pseudocode.
>
> b) How would you keep `accountInfo.html` as a static page, but prevent the attack from part (a)? You need only change line (\*) and `userdata.js`. Make sure to explain why your defense prevents the attack. (Hint: Try loading the user's data in a way that gives bank.com access to the data, but does not give `evil.com` access. In particular, `userdata.js` need not be a Javascript file)

## 4

> **CSRF Defenses**
>
> a) In class we discussed Cross Site Request Forgery (CSRF) attacks against websites that rely solely on cookies for session management. Briefly explain a CSRF attack on such a site.
>
> b) A common CSRF defense places a token in the DOM of every page (e.g., as a hidden form element) in addition to the cookie. An HTTP request is accepted by the server only if it contains both a valid HTTP cookie header and a valid token in the POST parameters. Why does this prevent the attack from part (a)?
>
> c) One approach to choosing a CSRF token is to choose one at random. Suppose a web server chooses the token as a fresh random string for every HTTP response. The server checks that this random string is present in the next HTTP request for that session. Does this prevent CSRF attacks? If so, explain why. If not, describe an attack.
>
> d) Another approach is to choose the token as a fixed random string chosen by the server. That is, the same random string is used as the CSRF token in all HTTP responses from the server over a given time period. Does this prevent CSRF attacks? If so, explain why. If not, describe an attack.
> e) Why is the Same-Origin Policy important for the cookie-plus-token defense?

## 5

> Recall that content security policy (CSP) is an HTTP header sent by a web site to the browser that tells the browser what it should and should not do as it is processing the content. The purpose of this question is to explore a number of CSP directives. Please use the CSP [specification](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) to look up the definition of the directives in the questions below.
>
> a) Explain what the following CSP header does: `Content-Security-Policy: script-src 'self'`; What is the purpose of this CSP directive? What attack is it intended to prevent?
>
> b) What does the following CSP header do: `Content-Security-Policy: frame-ancestors 'none'`; What attack does it prevent?
>
> c) What does the following CSP header do: `Content-Security-Policy: sandbox 'allow-scripts'`; Suppose a page loaded from the domain `www.xyz.com` has the sandbox CSP header, as above. This causes the page to be treated as being from a special origin that always fails the same-origin policy, among other restrictions. How does this impact the page's ability to read cookies belonging to `www.xyz.com` using Javascript? Give an example where a web site might want to use this CSP header.

## 6

> **Stealth Port Scanning**
>
> Recall that the IP packet header contains a 16-bit identification field that is used for assembling packet fragments. IP mandates that the identification field be unique for each packet for a given (SourceIP,DestIP) pair. A common method for implementing the identification field is to maintain a single counter that is incremented by one for every packet sent. The current value of the counter is embedded in each outgoing packet. Since this counter is used for all connections to the host we say that the host implements a global identification field.
>
> a) Suppose a host P (whom we'll call the Patsy for reasons that will become clear later) implements a global identification field. Suppose further that P responds to ICMP ping requests. You control some other host A. How can you test if P sent a packet to anyone (other than A) within a certain one minute window? You are allowed to send your own packets to P.
>
> b) Your goal now is to test whether a victim host V is running a server that accepts connections to port n (that is, test if V is listening on port n). You wish to hide the identity of your machine A and therefore A cannot directly send a packet to V, unless that packet contains a spoofed source IP address. Explain how to use the patsy host P to test if V accepts connections to port n.
>
> Hint: Recall the following facts about TCP:
>
> - A host that receives a SYN packet to an open port n sends back a SYN/ACK
response to the source IP.
> - A host that receives a SYN packet to a closed port n sends back a RST packet to the source IP.
> - A host that receives a SYN/ACK packet that it is not expecting sends back a RST packet to the source IP.
> - A host that receives a RST packet sends back no response.

## 7

> **Denial of Service attacks**
>
> a) Using a TCP SYN spoofing attack, the attacker aims to flood the table of TCP connection requests on a system so that it is unable to respond to legitimate connection requests. Consider a server system with a table for 256 connection requests. This system will retry sending the SYN-ACK packet five times when it fails to receive an ACK packet in response, at 30 second intervals, before purging the request from its table. Assume that no additional countermeasures are used against this attack and that the attacker has filled this table with an initial flood of connection requests. At what rate must the attacker continue to send TCP connection requests to this system in order to ensure that the table remains full? Assuming that the TCP SYN packet is 40 bytes in size (ignoring framing overhead), how much bandwidth does the attacker consume to continue this attack?
>
> b) In order to implement a DNS amplification attack, the attacker must trigger the creation of a sufficiently large volume of DNS response packets from the intermediary to exceed the capacity of the link to the target organization. Consider an attack where the DNS response packets are 500 bytes in size (ignoring framing overhead). How many of these packets per second must the attacker trigger to flood a target organization using a 0.5-Mbps link? A 2-Mbps link? Or a 10-Mbps link? If the DNS request packet to the intermediary is 60 bytes in size, how much bandwidth does the attacker consume to send the necessary rate of DNS request packets for each of these three cases?


