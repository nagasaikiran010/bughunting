## GAMEPLAN 

## 1
What is a Checklist! 
why we need a checklist
do i have a checklist 
do we have to follow one ??  


## 2
What is mindset for a bug hunter?
does it matter ?
what mindset i follow ?
what should be my mindset ?

## 3 - target
How to choose target !
	1. Funtion ?
	2. Wildcard ? *.domain.tld
	3. range! xxx.xxx.xxx.0/24
	4. attack surface ! 
	5. Acq!
	6. Policy!
Platform matters ??
Response time ??
How to find good programs 



## 4 - subd
Methods i can use 
what tools i can use?
	1. bbot 
	2. amass
	3. crt.sh 
	4. source codes
	5. knockpy
	6. subfinder
	7. aquatone
	8. subdomainzer
	9. altDNS
	10. Security Trails api
Levels of subdomain 
	domain.com
	sub.domain.com
	sub.sub.fdomain.com
	sub.sub.sub.domain.com

bruteforcing > worldist > try1.domain.com 



how to find 
hidden subdomain >> 
sources for subdomains 



## 5 DNS Enum
  it's the act of detecting and enumerating all possible DNS records from a domain name. This includes hostnames, DNS record names, DNS record types, TTLs, IP addresses, and a bit more, depending on how much information you're looking for.
what tools can i use ?
	1. DIG
	2. Host
	3. NMAP (nmap -T4 -p --script dns-brute domain.tld)
	4. DNS Recon
	5. SecurityTrails
Importance ??

## 6 Whois Recon
what is whois 
why we need to do this 
Types of whois 	
	1. Thin Model (registrar name, domain registration dates and name servers used)
	2. Thick Model (the thick WHOIS model expands the information, adding such details as registrar, technical and administrative details)
Importance?
	1. track phishing 
	2. Used in legal works 
Lets do it !!

## 7 Server Identification !
what is server 
types of server
why we need to find it 
can it helps us ?
lets do it !
How to find exploits of it !
is it impoertant ?

## 8 TECH-STACK
What are technology stack? 
why we need to find it?
can we find bugs from it ?
how to do it ?
tools to use ?
reaplcements ??


## 9 SSL/TLS
TLS Transport Layer Security
SSL Secure Sockets Layer
DO we have to do it ?
what info we will get ?
Tools we can use ?
	1. tlsx

## 10 Network Scanning (Attaching a video on it)

## 11 Ports 
why we need to scan ports 
is it important
which ports to scan 
is it realted to portals ?
how to scan then 
what tools to use?
	1. Nmap 
	2. RustScan 
	3. Unicornscan

## 12 Portals 
what are portals?
Why we need to find
default creds
leaked creds 
what to look in portals 

## 13 Dir Enum 
what is this ?
why we do this ?
is it really importanT?
what info we can find from it ?
tools we can use ? 
	1. Dirb
	2. Gobuster
	3. Dirsearch 
Do we have to use wordlist ? 
can we use FFUF ?

## 14 File Enum
what is this ?
why we do this ?
is it really importanT?
what info we can find from it ?
**REST IS SAME** 
What Wordlist we can use ?
is it diffrent from dirb
**attched video might help

		https://domain.tld/ngnix/FUZZ

## 15 Third Party Game
**it can be a game changer** !!
what is it exactly ?
How to Detect them 
how to find vulnerabilities in it ?
what if there is something left ?
How to exploit them ?

## 16 WAF MISCONFIG
What are waf 
friend or enemy ?
How to find misconfigs 
**Resources are attached**
how to find if they are impactful ?
Lets take a look !

dir.com/hacker/db.txt
Search the domain on shodan > get ip > dir.com / ip


## 17 CDN 
CDN vs WAF ?
CDN is deployed at the ingress layer to accelerate content distribution. WAF is deployed at the intermediate layer to protect applications
Even without a WAF, CDNs protect your website against DDoS attacks which overload your original server with fake traffic to slow down or even crash your website
How to look for something in them ?


## 17 Alive subz
Why we need them ?
what about other dead subs?
what addionally we can do ?
tools we can use?	
	1. httpx
			https://domain.tld > saves > if 200 ok

	2. httprobe
			https://
			http://

Both gives diffrent results!
why we need both ?
lets learn to use them !

## 18 IP RECON
**GAME CHANGER**
what is this?
why we need to do it ?
how can we do this ?
what info we get from here ?
what will be use ??
what automations we can use ??

Conditions! > target is waildcard but no ip are given 
IP : 
shodan/cli > collect all ip : shodan cli> find all open ports : rustscan / Nmap > find all portals > find all the dashboards, services, and all the files > you do fuzzing FUFF


## 19 NMAP 
refer to ##10 ##5 ##11
Lets use NMAP for advanced methods
NSE
How can we use NMAP for Multiple things!



## 20 NSE
What is NSE 
why we can use it
how to use it for hunting?
How it is gonna work !
Lets use it !

## 21 AUTOMATED IP RECON TOOL
Check attached python recon tool that helps in it
lets use it 

shodan / ip > Rustscan / ports > nuclei (Specific tempaltes) dashboards portals bigs expired servies > FUZZ or !



## 22 ASN Autonomous System Number
Perform ASN lookups as shown in the examples below. Enter either as a single query, a list (IP's or AS Numbers) or a comma separated list.
Why we need to do this recon ?
ASN is that important?
what tools we can use ?
	1. asnrecon
	2. asnmap
Lets do it !

## 23 NetCraft
Netcraft is an Internet monitoring company that monitors uptimes and provides server operating system detection as well as a number of other services. Netcraft has an online search tool that allows users to query its databases for host information.
Lets take a look on it !

## 24 REV-IP
What is reev-ip lookup ?
A reverse IP domain check takes a domain name or IP address pointing to a web server and searches for other sites known to be hosted on that same web server.
why we need to do it?
Let's do it Practically ! 
https://www.yougetsignal.com/ 

## 25 Web Based 
**IT CAN BE A GAMECHANGER**
what is the web ?
what we will do ?
LEta take a look on the following web
	1. https://bgp.he.net/

**LETS JUST JUMP ON THEM**


## 26 Google Dorking
what is this ? 
Lets Use this https://github.com/Vaidik-pandya/Google-dorks-by-vaidik-pandya

## 27 Gituhb Dorking
what is this ?
Lets use this https://github.com/Vaidik-pandya/Github_recon_dorks/blob/main/gitdork.txt

## 28 Shodan Dorking
what is this ?
https://github.com/humblelad/Shodan-Dorks


## 29 ZOOMEYE
what is this ?
Why this instead of shodan?
Lets do it live !

## 30 Spidering 
What is this ?
why we need to crawl ?
is it really important
what we need to look after we crawl ?
what tools we can use ?
	1. Spider in Burp 
	2. Paramspider
	3. Scarpy
	4. Go_spider
	5. aspider
	6. ParamPAMPAM
Let's do it !

## 31 BruteFOrcing
What is it ?
 In brute force, the attacker uses valid data, for example, to check if a login attempt works. But with Fuzzing, they can send random data to break the expected behavior of a system
What resource collection we can use ?
What tools we can use ?
	1. Go-buster
	2. dirsearch 
	3. ssb - ssh brute 
	4. Callow -custom tools for logins
	5. Ncrack - network 

## 32 File Enum 
What is it?
tools we can use ?
		1. ffuf
		2. Gobuster
these are my favssss
What wordlist we can use ?
what files we are looking for ?
what resources we need to use 
lets explore them !

## 33 Endpoints recon ! 
what are endponits to use ?
how to find them 
how to identify them 
how to look for something on them 
what techniques we can use 
What tools we can use 
	1. Arjun
	2. XnlLinkFinder
		Many more things in it
Lets do it Live

## 34 JS recon 
Why js is imp ?
what we need to look on it ?
how to find info disc from it 
how to find js files  > wayback / Crawling / Source code / Bruteforcing / DOrking
tools we can use !
	1. JSFScan
	2. AnalyseJS
	3. Nuclei 
Sources to find JS file
How do i do this recon !


## 35 FINDING HIDDEN INFORMATIONS

## 36 Parameter Discovery
What is this
The easiest active way to discover URLs and corresponding parameters on the target is to crawl the site.

Now i Gues you got it !
Why it is so important 
Lets make it Happen 

## 37 Token handling
Why we need to understand this ?
what bugs can be here?
how to leak token from here
what sources we need 

## 38 FUZZING 
**refer to BRUTEFORCING**
What addionals thing we have to look for ?
what special resource we have to use ?
Lets do it !

## 39  Info Leaks
**THE CLIMAX BOIII**
IF you combine everyting this is what we are looking for

ALL steps above and few addional resources can help
Lets take a look 

## 40 TOken leaks
Lets take a look 


## 41 Source code leaks
Lets take a look 


## 42 Backup Leaks
Lets take a look 


## 43 API Leaks
Lets take a look 


## 44 DataBase Leaks
Lets take a look 


## 45 Third Party leaks 
Check older tags 
Lets take a look 

## 46 Logs and internel files Disclosure
Lets take a look 

## 47  Server Leaks

## 48 Header Analysis
What are headers 
why we need to do this ?
How can we do it 
Let's do it !

## 49 Request Analysis
What is a web req?
how to analyize it ?
lets do it

## 50 Chrome Extension
What Extension you need ??
What they can do ?
What Extensions we need ?
	1. foxyproxy
	2. PwnFox
	3. HackTools
	4. Wappalyzer
	5. Shodan
	6. DotGit
	7. Cookie-editor
	8. s3 Bucket list
	9. Hackbar
	10. Hunter
	11. Modify header value
	12. retire.js 
	13. Multiple URLs
	14. JSON Formatter
	15. Firefox relay
Let's do it

## 51 Sanitization Checks 
What is Sanitization
how to identify it ?
Let's do it

## 52 Burp Extensions 
Is it effective ?
which ones ?
	Store 
		1. Logger++
		2. Autorize
		3. Turbo Intruder
		4. J2EE Scan 
		5. JSON Beautifier 
		6. AuthMatrix
		7. ParamMiner
		8. BurpBountyPro
		9. AWS Seurity Checks
		10. SQLiPy Integrated
		11. SAML Reader

## 54 Using websites for recon 
Let's Do it 

## 55 Visual Recon 
What is this?
Why we need to do it ?
Is that really that muhc helpful ?
What tools we can use 
	1. Eyewitness
	2. Gowitness
How to get bugs from it
Let's do it.


## 56 Manual Observations
What to do in it ?
Few things : 
The parent comany / acq  > p1 or p2 & any bug that affects main or incose things
flows > recon / 12 horus >> manual obersvation on the user / comany 

## 57 Behaviour Analysis and WebFlow
What is this 
how to do it 

## 58 Correct way to use tools 	

## 59 How to use this info to get bounties 

## 60 How to Hunt



Add to scope > 1.7x > wait

Waymore / spirders / gather all error pages / path disclosres / fuzzing results / bruteforcing / js files / 


Tools atttached:
databud : 
damnip : 
script
grep list
resource bundle
poc collecrtions
methes 

disclaimer

