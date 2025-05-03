Description of this bug:
When an origin IP address is found on Cloudflare, it typically refers to discovering the real IP address of a server or a device that is protected by Cloudflare's reverse proxy service. 

STEPS TO REPRODUCE

1. GO TO THIS URL : https://www.shodan.io/search?query=ssl.cert.subject.cn%3Ajora.com
2. Here is the ip 
     --> 54.252.50.116
     --> 54.66.83.184
     --> 13.237.156.41
     --> 13.211.43.152
     --> 13.210.242.22
3.  These all ip's redirected to jora.com 
impact : 

- Exposing the origin IP address can bypass Cloudflare's security measures, potentially exposing the server to direct attacks.
- Attackers could potentially bypass protections provided by Cloudflare, such as DDoS mitigation and WAF (Web Application Firewall) rules.