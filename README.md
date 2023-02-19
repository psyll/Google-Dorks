# Google Dorks

![Google Dorks](assets/img/header.png "Google Dorks")

<p align="center">
	<a href="https://github.com/psyll/Google-Dorks/blob/master/LICENSE">
		<img src="https://badgen.net/badge/license/mit" alt="Display">
	</a>
	<img src="https://img.shields.io/github/repo-size/psyll/Google-Dorks" alt="Repo Size">
	<img src="https://img.shields.io/github/languages/code-size/psyll/Google-Dorks" alt="Code Size">
	<img src="https://img.shields.io/github/last-commit/psyll/Google-Dorks" alt="Last commit">
	<img src="https://img.shields.io/github/issues-raw/psyll/Google-Dorks" alt="Open issues">

</p>

## Explanations

### cache

If you include other words in the query, Google will highlight those words within the cached document. For instance, `[cache:www.google.com web]` will show the cached content with the word “web” highlighted. This functionality is also accessible by clicking on the “Cached” link on Google’s main results page. The query `[cache:]` will show the version of the web page that Google has in its cache. For instance, `[cache:www.google.com]` will show Google’s cache of the Google homepage. Note there can be no space between the “cache:” and the web page url.

### link

The query `[link:]` will list webpages that have links to the specified webpage.For instance, `[link:www.google.com]` will list webpages that have links pointing to the Google homepage. Note there can be no space between the “link:” and the web page url.

### related

The query `[related:]` will list web pages that are “similar” to a specified web page. For instance, `[related:www.google.com]` will list web pages that are similar to	the Google homepage. Note there can be no space between the “related:” and the webpage url.

### info

The query `[info:]` will present some information that Google has about that web	page. For instance, `[info:www.google.com]` will show information about the Google homepage. Note there can be no space between the “info:” and the web page url.

### define
The query `[define:]` will provide a definition of the words you enter after it, gathered from various online sources. The definition will be for the entire phrase entered (i.e., it will include all the words in the exact order you typed them).

### stocks

If you begin a query with the `[stocks:]` operator, Google will treat the rest of the query terms as stock ticker symbols, and will link to a page showing stock information for those symbols. For instance, [stocks: intc yhoo] will show information about Intel and Yahoo. (Note you must type the ticker symbols, not the company name.)

### site

If you include `[site:]` in your query, Google will restrict the results to those	websites in the given domain. For instance, [help site:www.google.com] will find pages about help within www.google.com. [help site:com] will find pages about help within
.com urls. Note there can be no space between the “site:” and the domain.

### allintitle
If you start a query with `[allintitle:]`, Google will restrict the results to those with all of the query words in the title. For instance, [allintitle: google search] will return only documents that have both “google” and “search” in the title.

### intitle

If you include `[intitle:]` in your query, Google will restrict the results to documents containing that word in the title. For instance, [intitle:google search]	will return documents that mention the word “google” in their title, and mention the 	word “search” anywhere in the document (title or no). Note there can be no space between the “intitle:” and the following word. Putting `[intitle:]` in front of every word in your query is equivalent to putting `[allintitle:]` at the front of your	query: [intitle:google intitle:search] is the same as [allintitle: google search].

### allinurl

If you start a query with `[allinurl:]`, Google will restrict the results to those with all of the query words in the url. For instance, [allinurl: google search] will return only documents that have both “google” and “search” in the url. Note that `[allinurl:]` works on words, not url components. In particular, it ignores punctuation. Thus, [allinurl: foo/bar] will restrict the results to page with the words “foo” and “bar” in the url, but won’t require that they be separated by a slash within that url, that they be adjacent, or that they be in that particular word order. There is currently no way to enforce these constraints.

### inurl

If you include `[inurl:]` in your query, Google will restrict the results to documents containing that word in the url. For instance, `[inurl:google search]` will return documents that mention the word “google” in their url, and mention the word “search” anywhere in the document (url or no). Note there can be no space between	the “inurl:” and the following word. Putting “inurl:” in front of every word in your query is equivalent to putting “allinurl:” at the front of your query: `[inurl:google inurl:search]` is the same as `[allinurl: google search]`.

## Popular Dorks List

|  |
|---|
"Nina Simone intitle:”index.of” “parent directory” “size” “lastmodified” “description” I Put A Spell On You (mp4|mp3|avi|flac|aac|ape|ogg) -inurl:(jsp|php|html|aspx|htm|cf|shtml|lyrics-realm|mp3-collection) -site:.info|
Bill Gates intitle:”index.of” “parent directory” “size” “last modified” “description” Microsoft (pdf|txt|epub|doc|docx) -inurl:(jsp|php|html|aspx|htm|cf|shtml|ebooks|ebook) -site:.info
parent directory /appz/ -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory DVDRip -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Xvid -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Gamez -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory MP3 -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Name of Singer or album -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
filetype:config inurl:web.config inurl:ftp
“Windows XP Professional” 94FBR
ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:"budget approved") inurl:confidential
ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:”budget approved”) inurl:confidential
ext:inc "pwd=" "UID="
ext:ini intext:env.ini
ext:ini Version=... password
ext:ini Version=4.0.0.4 password
ext:ini eudora.ini
ext:ini intext:env.ini
ext:log "Software: Microsoft Internet Information Services *.*"
ext:log "Software: Microsoft Internet Information
ext:log "Software: Microsoft Internet Information Services *.*"
ext:log \"Software: Microsoft Internet Information Services *.*\"
ext:mdb   inurl:*.mdb inurl:fpdb shop.mdb
ext:mdb inurl:*.mdb inurl:fpdb shop.mdb
ext:mdb inurl:*.mdb inurl:fpdb shop.mdb
filetype:SWF SWF
filetype:TXT TXT
filetype:XLS XLS
filetype:asp   DBQ=" * Server.MapPath("*.mdb")
filetype:asp "Custom Error Message" Category Source
filetype:asp + "[ODBC SQL"
filetype:asp DBQ=" * Server.MapPath("*.mdb")
filetype:asp DBQ=\" * Server.MapPath(\"*.mdb\")
filetype:asp “Custom Error Message” Category Source
filetype:bak createobject sa
filetype:bak inurl:"htaccess|passwd|shadow|htusers"
filetype:bak inurl:\"htaccess|passwd|shadow|htusers\"
filetype:conf inurl:firewall -intitle:cvs
filetype:conf inurl:proftpd. PROFTP FTP server configuration file reveals
filetype:dat "password.dat
filetype:dat \"password.dat\"
filetype:eml eml +intext:"Subject" +intext:"From" +intext:"To"
filetype:eml eml +intext:\"Subject\" +intext:\"From\" +intext:\"To\"
filetype:eml eml +intext:”Subject” +intext:”From” +intext:”To”
filetype:inc dbconn
filetype:inc intext:mysql_connect
filetype:inc mysql_connect OR mysql_pconnect
filetype:log inurl:"password.log"
filetype:log username putty PUTTY SSH client logs can reveal usernames
filetype:log “PHP Parse error” | “PHP Warning” | “PHP Error”
filetype:mdb inurl:users.mdb
filetype:ora ora
filetype:ora tnsnames
filetype:pass pass intext:userid
filetype:pdf "Assessment Report" nessus
filetype:pem intext:private
filetype:properties inurl:db intext:password
filetype:pst inurl:"outlook.pst"
filetype:pst pst -from -to -date
filetype:reg reg +intext:"defaultusername" +intext:"defaultpassword"
filetype:reg reg +intext:\"defaultusername\" +intext:\"defaultpassword\"
filetype:reg reg +intext:â? WINVNC3â?
filetype:reg reg +intext:”defaultusername” +intext:”defaultpassword”
filetype:reg reg HKEY_ Windows Registry exports can reveal
filetype:reg reg HKEY_CURRENT_USER SSHHOSTKEYS
filetype:sql "insert into" (pass|passwd|password)
filetype:sql ("values * MD5" | "values * password" | "values * encrypt")
filetype:sql (\"passwd values\" | \"password values\" | \"pass values\" )
filetype:sql (\"values * MD\" | \"values * password\" | \"values * encrypt\")
filetype:sql +"IDENTIFIED BY" -cvs
filetype:sql password
filetype:sql password
filetype:sql “insert into” (pass|passwd|password)
filetype:url +inurl:"ftp://" +inurl:";@"
filetype:url +inurl:\"ftp://\" +inurl:\";@\"
filetype:url +inurl:”ftp://” +inurl:”;@”
filetype:xls inurl:"email.xls"
filetype:xls username password email
index of: intext:Gallery in Configuration mode
index.of passlist
index.of perform.ini mIRC IRC ini file can list IRC usernames and
index.of.dcim
index.of.password
intext:" -FrontPage-" ext:pwd inurl:(service | authors | administrators | users)
intext:""BiTBOARD v2.0" BiTSHiFTERS Bulletin Board"
intext:"# -FrontPage-" ext:pwd inurl:(service | authors | administrators | users) "# -FrontPage-" inurl:service.pwd
intext:"#mysql dump" filetype:sql
intext:"#mysql dump" filetype:sql 21232f297a57a5a743894a0e4a801fc3
intext:"A syntax error has occurred" filetype:ihtml
intext:"ASP.NET_SessionId" "data source="
intext:"About Mac OS Personal Web Sharing"
intext:"An illegal character has been found in the statement" -"previous message"
intext:"AutoCreate=TRUE password=*"
intext:"Can't connect to local" intitle:warning
intext:"Certificate Practice Statement" filetype:PDF | DOC
intext:"Certificate Practice Statement" inurl:(PDF | DOC)
intext:"Copyright (c) Tektronix, Inc." "printer status"
intext:"Copyright © Tektronix, Inc." "printer status"
intext:"Emergisoft web applications are a part of our"
intext:"Error Diagnostic Information" intitle:"Error Occurred While"
intext:"Error Message : Error loading required libraries."
intext:"Establishing a secure Integrated Lights Out session with" OR intitle:"Data Frame - Browser not HTTP 1.1 compatible" OR intitle:"HP Integrated Lights-
intext:"Fatal error: Call to undefined function" -reply -the -next
intext:"Fill out the form below completely to change your password and user name. If new username is left blank, your old one will be assumed." -edu
intext:"Generated   by phpSystem"
intext:"Generated by phpSystem"
intext:"Host Vulnerability Summary Report"
intext:"HostingAccelerator" intitle:"login" +"Username" -"news" -demo
intext:"IMail Server Web Messaging" intitle:login
intext:"Incorrect syntax near"
intext:"Index of" /"chat/logs"
intext:"Index of /network" "last modified"
intext:"Index of /" +.htaccess
intext:"Index of /" +passwd
intext:"Index of /" +password.txt
intext:"Index of /admin"
intext:"Index of /backup"
intext:"Index of /mail"
intext:"Index of /password"
intext:"Microsoft (R) Windows * (TM) Version * DrWtsn32 Copyright (C)" ext:log
intext:"Microsoft CRM : Unsupported Browser Version"
intext:"Microsoft ® Windows * ™ Version * DrWtsn32 Copyright ©" ext:log
intext:"Network Host Assessment Report" "Internet Scanner"
intext:"Network Vulnerability   Assessment Report"
intext:"Network Vulnerability Assessment Report"
intext:"Network Vulnerability Assessment Report" 本文来自 pc007.com
intext:"SQL Server Driver][SQL Server]Line 1: Incorrect syntax near"
intext:"Thank you for your order"   +receipt
intext:"Thank you for your order" +receipt
intext:"Thank you for your purchase" +download
intext:"The following report contains confidential information" vulnerability -search
intext:"phpMyAdmin MySQL-Dump" "INSERT INTO" -"the"
intext:"phpMyAdmin MySQL-Dump" filetype:txt
intext:"phpMyAdmin" "running on" inurl:"main.php"
intextpassword | passcode)   intextusername | userid | user) filetype:csv
intextpassword | passcode) intextusername | userid | user) filetype:csv
intitle:"index of" +myd size
intitle:"index of" etc/shadow
intitle:"index of" htpasswd
intitle:"index of" intext:connect.inc
intitle:"index of" intext:globals.inc
intitle:"index of" master.passwd
intitle:"index of" master.passwd 007电脑资讯
intitle:"index of" members OR accounts
intitle:"index of" mysql.conf OR mysql_config
intitle:"index of" passwd
intitle:"index of" people.lst
intitle:"index of" pwd.db
intitle:"index of" spwd
intitle:"index of" user_carts OR user_cart
intitle:"index.of *" admin news.asp configview.asp
intitle:("TrackerCam Live Video")|("TrackerCam Application Login")|("Trackercam Remote") -trackercam.com
intitle:(“TrackerCam Live Video”)|(“TrackerCam Application Login”)|(“Trackercam Remote”) -trackercam.com
inurl:admin inurl:userlist Generic userlist files

## All dorks list

| |
|---|
!Host=*.* intext:enc_UserPassword=* ext:pcf
" -FrontPage-" ext:pwd inurl:(service | authors | administrators | users)
"# -FrontPage-" ext:pwd inurl:(service | authors | administrators | users) "# -FrontPage-" inurl:service.pwd
"#mysql dump" filetype:sql
"#mysql dump" filetype:sql 21232f297a57a5a743894a0e4a801fc3
"'dsn: mysql:host=localhost;dbname=" ext:yml | ext:txt "password:"
"* Authentication Unique Keys and Salts" ext:txt | ext:log
"-- Dumped from database version" + "-- Dumped by pg_dump version" ext:txt | ext:sql | ext:env | ext:log
"-- Dumping data for table `admin`" | "-- INSERT INTO `admin`" "VALUES" ext:sql | ext:txt | ext:log | ext:env
"-- Server version" "-- MySQL Administrator dump 1.4" ext:sql
": vBulletin Version 1.1.5"
"A syntax error has occurred" filetype:ihtml
"About Mac OS Personal Web Sharing"
"access denied for user" "using password"
"allow_call_time_pass_reference" "PATH_INFO"
"An illegal character has been found in the statement" -"previous message"
"apricot - admin" 00h
"ASP.NET_SessionId" "data source="
"AutoCreate=TRUE password=*"
"bp blog admin" intitle:login | intitle:admin -site:johnny.ihackstuff.com
"Can't connect to local" intitle:warning
"Certificate Practice Statement" inurl:(PDF | DOC)
"change the Administrator Password." intitle:"HP LaserJet" -pdf
"Chatologica MetaSearch" "stack tracking"
"Chatologica MetaSearch" "stack tracking:"
"DefaultPassword" ext:reg "[HKEY_LOCAL_MACHINESOFTWAREMicrosoftWindows NTCurrentVersionWinlogon]"
"define('DB_USER'," + "define('DB_PASSWORD'," ext:txt
"define('SECURE_AUTH_KEY'" + "define('LOGGED_IN_KEY'" + "define('NONCE_KEY'" ext:txt | ext:cfg | ext:env | ext:ini
"detected an internal error [IBM][CLI Driver][DB2/6000]"
"Duclassified" -site:duware.com "DUware All Rights reserved"
"duclassmate" -site:duware.com
"Dudirectory" -site:duware.com
"dudownload" -site:duware.com
"Dumping data for table"
"DUpaypal" -site:duware.com
"Elite Forum Version *.*"
"Emergisoft web applications are a part of our"
"Error Diagnostic Information" intitle:"Error Occurred While"
"error found handling the request" cocoon filetype:xml
"Establishing a secure Integrated Lights Out session with" OR intitle:"Data Frame - Browser not HTTP 1.1 compatible" OR intitle:"HP Integrated Lights-
"Fatal error: Call to undefined function" -reply -the -next
"ftp://" "www.eastgame.net"
"Host Vulnerability Summary Report"
"HostingAccelerator" intitle:"login" +"Username" -"news" -demo
"html allowed" guestbook
"http://*:*@www" domainname
"HTTP_FROM=googlebot" googlebot.com "Server_Software="
"iCONECT 4.1 :: Login"
"IMail Server Web Messaging" intitle:login
"Incorrect syntax near"
"Index of /" +.htaccess
"Index of /" +passwd
"Index of /" +password.txt
"Index of /admin"
"Index of /backup"
"Index of /mail"
"Index Of /network" "last modified"
"Index of /password"
"index of /private" -site:net -site:com -site:org
"index of /private" site:mil
"index of" "/home/000~ROOT~000/etc"
"Index of" / "chat/logs"
"index of" inurl:database ext:sql | xls | xml | json | csv
"index of/" "ws_ftp.ini" "parent directory"
"inspanel" intitle:"login" -"cannot" "Login ID" -site:inspediumsoft.com
"Installed Objects Scanner" inurl:default.asp
"Internal Server Error" "server at"
"intitle:3300 Integrated Communications Platform" inurl:main.htm
"intitle:index of"
"Invision Power Board Database Error"
"keystorePass=" ext:xml | ext:txt -git -gitlab
"Link Department"
"liveice configuration file" ext:cfg
"liveice configuration file" ext:cfg -site:sourceforge.net
"Login - Sun Cobalt RaQ"
"login prompt" inurl:GM.cgi
"Login to Usermin" inurl:20000
"MacHTTP" filetype:log inurl:machttp.log
"mailer_password:" + "mailer_host:" + "mailer_user:" + "secret:" ext:yml
"Mecury Version" "Infastructure Group"
"Microsoft (R) Windows * (TM) Version * DrWtsn32 Copyright (C)" ext:log
"Microsoft CRM : Unsupported Browser Version"
"Microsoft ® Windows * ™ Version * DrWtsn32 Copyright ©" ext:log
"More Info about MetaCart Free"
"Most Submitted Forms and s?ri?ts" "this section"
"Most Submitted Forms and Scripts" "this section"
"mysql dump" filetype:sql
"mySQL error with query"
"Network Host Assessment Report" "Internet Scanner"
"Network Vulnerability Assessment Report"
"not for distribution" confidential
"not for public release" -.edu -.gov -.mil
"OPENSRS Domain Management" inurl:manage.cgi
"ORA-00921: unexpected end of SQL command"
"ORA-00933: SQL command not properly ended"
"ORA-00936: missing expression"
"ORA-12541: TNS:no listener" intitle:"error occurred"
"Output produced by SysWatch *"
"parent directory " /appz/ -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
"parent directory " DVDRip -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
"parent directory " Gamez -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
"parent directory " MP3 -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
"parent directory " Name of Singer or album -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
"parent directory "Xvid -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
"parent directory" +proftpdpasswd
"Parse error: parse error, unexpected T_VARIABLE" "on line" filetype:php
"pcANYWHERE EXPRESS Java Client"
"phone * * *" "address *" "e-mail" intitle:"curriculum vitae"
"Phorum Admin" "Database Connection" inurl:forum inurl:admin
"phpMyAdmin MySQL-Dump" "INSERT INTO" -"the"
"phpMyAdmin MySQL-Dump" filetype:txt
"phpMyAdmin" "running on" inurl:"main.php"
"Please authenticate yourself to get access to the management interface"
"please log in"
"Please login with admin pass" -"leak" -sourceforge
"PostgreSQL query failed: ERROR: parser: parse error"
"Powered by mnoGoSearch - free web search engine software"
"powered by openbsd" +"powered by apache"
"Powered by UebiMiau" -site:sourceforge.net
"Powered by vBulletin(R) Version 5.6.3"
"powered | performed by Beyond Security's Automated Scanning" -kazaa -example
"produced by getstats"
"putty.log" ext:log | ext:cfg | ext:txt | ext:sql | ext:env
"Request Details" "Control Tree" "Server Variables"
"robots.txt" "Disallow:" filetype:txt
"Running in Child mode"
"secret_key_base:" ext:exs | ext:txt | ext:env | ext:cfg
"Select a database to view" intitle:"filemaker pro"
"set up the administrator user" inurl:pivot
"sets mode: +k"
"sets mode: +p"
"sets mode: +s"
"Shadow Security Scanner performed a vulnerability assessment"
"site info for" "Enter Admin Password"
"SnortSnarf alert page"
"SQL Server Driver][SQL Server]Line 1: Incorrect syntax near"
"SquirrelMail version" "By the SquirrelMail development Team"
"Supplied argument is not a valid MySQL result resource"
"Supplied argument is not a valid PostgreSQL result"
"Syntax error in query expression " -the
"SysCP - login"
"System" + "Toner" + "Input Tray" + "Output Tray" inurl:cgi
"Thank you for your order" +receipt
"The following report contains confidential information" vulnerability -search
"The s?ri?t whose uid is " "is not allowed to access"
"The script whose uid is " "is not allowed to access"
"The SQL command completed successfully." ext:txt | ext:log
"The statistics were last upd?t?d" "Daily"-microsoft.com
"There are no Administrators Accounts" inurl:admin.php -mysql_fetch_row
"There seems to have been a problem with the" " Please try again by clicking the Refresh button in your web browser."
"This is a restricted Access Server" "Javas?ri?t Not Enabled!"|"Messenger Express" -edu -ac
"This is a Shareaza Node"
"this proxy is working fine!" "enter *" "URL***" * visit
"This report lists" "identified by Internet Scanner"
"This report was generated by WebLog"
"This section is for Administrators only. If you are an administrator then please"
"This summary was generated by wwwstat"
"Traffic Analysis for" "RMON Port * on unit *"
"ttawlogin.cgi/?action="
"Unable to jump to row" "on MySQL result index" "on line"
"Unclosed quotation mark before the character string"
"Version Info" "Boot Version" "Internet Settings"
"VHCS Pro ver" -demo
"VNC Desktop" inurl:5800
"Warning: Bad arguments to (join|implode) () in" "on line" -help -forum
"Warning: Cannot modify header information - headers already sent"
"Warning: Division by zero in" "on line" -forum
"Warning: mysql_connect(): Access denied for user: '*@*" "on line" -help -forum
"Warning: mysql_query()" "invalid query"
"Warning: pg_connect(): Unable to connect to PostgreSQL server: FATAL"
"Warning: Supplied argument is not a valid File-Handle resource in"
"Warning:" "failed to open stream: HTTP request failed" "on line"
"Warning:" "SAFE MODE Restriction in effect." "The s?ri?t whose uid is" "is not allowed to access owned by uid 0 in" "on line"
"Warning:" "SAFE MODE Restriction in effect." "The script whose uid is" "is not allowed to access owned by uid 0 in" "on line"
"Web File Browser" "Use regular expression"
"Web-Based Management" "Please input password to login" -inurl:johnny.ihackstuff.com
"WebExplorer Server - Login" "Welcome to WebExplorer Server"
"WebSTAR Mail - Please Log In"
"Welcome to Administration" "General" "Local Domains" "SMTP Authentication" inurl:admin
"Welcome to Intranet"
"Welcome to PHP-Nuke" congratulations
"Welcome to the Prestige Web-Based Configurator"
"xampp/phpinfo
"YaBB SE Dev Team"
"you can now password" | "this is a special page only seen by you. your profile visitors" inurl:imchaos
"You have an error in your SQL syntax near"
"You have requested access to a restricted area of our website. Please authenticate yourself to continue."
"You have requested to access the management functions" -.edu
"Your password is * Remember this for later use"
"your password is" filetype:log
( filetype:mail | filetype:eml | filetype:mbox | filetype:mbx ) intext:password|subject
("Indexed.By"|"Monitored.By") hAcxFtpScan
((inurl:ifgraph "Page generated at") OR ("This page was built using ifgraph"))
(intitle:"Please login - Forums
(intitle:"PRTG Traffic Grapher" inurl:"allsensors")|(intitle:"PRTG Traffic Grapher - Monitoring Results")
(intitle:"rymo Login")|(intext:"Welcome to rymo") -family
(intitle:"WmSC e-Cart Administration")|(intitle:"WebMyStyle e-Cart Administration")
(intitle:WebStatistica inurl:main.php) | (intitle:"WebSTATISTICA server") -inurl:statsoft -inurl:statsoftsa -inurl:statsoftinc.com -edu -software -rob
(inurl:"ars/cgi-bin/arweb?O=0" | inurl:arweb.jsp) -site:remedy.com -site:mil
(inurl:"robot.txt" | inurl:"robots.txt" ) intext:disallow filetype:txt
(inurl:/shop.cgi/page=) | (inurl:/shop.pl/page=)
**********/fid17013034EFB2509745A39CD861F4FEA3E716FBE5.aspx?s=
********.asp?cid=
********.php?cid=
********.php?id=
********.php?pid=
********s_in_area.asp?area_id=
********s_in_area.php?area_id=
****index/productinfo.php?id=
***zine/board.asp?board=
***zine/board.php?board=
*.php?include=
*.php?secc=
*inc*.php?adresa=
*inc*.php?base_dir=
*inc*.php?body=
*inc*.php?c=
*inc*.php?category=
*inc*.php?doshow=
*inc*.php?ev=
*inc*.php?get=
*inc*.php?i=
*inc*.php?inc=
*inc*.php?include=
*inc*.php?j=
*inc*.php?k=
*inc*.php?ki=
*inc*.php?left=
*inc*.php?m=
*inc*.php?menu=
*inc*.php?modo=
*inc*.php?open=
*inc*.php?pg=
*inc*.php?rub=
*inc*.php?sivu=
*inc*.php?start=
*inc*.php?str=
*inc*.php?to=
*inc*.php?type=
*inc*.php?y=
-pub -pool intitle:\"index of\" \"Served by\" \"Web Server\"
-site:php.net -"The PHP Group" inurl:source inurl:url ext:pHp
/*.php?include=
/*.php?page=
/*.php?secc=
/*coppercop/theme.php?THEME_DIR=
/*default.php?****=
/*default.php?page=
/*inc*.php?****=
/*inc*.php?addr=
/*inc*.php?adresa=
/*inc*.php?base_dir=
/*inc*.php?c=
/*inc*.php?category=
/*inc*.php?doshow=
/*inc*.php?ev=
/*inc*.php?get=
/*inc*.php?i=
/*inc*.php?inc=
/*inc*.php?incl=
/*inc*.php?include=
/*inc*.php?j=
/*inc*.php?k=
/*inc*.php?ki=
/*inc*.php?left=
/*inc*.php?link=
/*inc*.php?m=
/*inc*.php?menu=
/*inc*.php?modo=
/*inc*.php?open=
/*inc*.php?pg=
/*inc*.php?rub=
/*inc*.php?showpage=
/*inc*.php?sivu=
/*inc*.php?start=
/*inc*.php?str=
/*inc*.php?to=
/*inc*.php?type=
/*inc*.php?y=
/*inc/header.php/step_one.php?server_inc=
/*inc/pipe.php?HCL_path=
/*include/new-visitor.inc.php?lvc_include_dir=
/*include/write.php?dir=
/*includes/header.php?systempath=
/*index.php?arquivo=
/*index.php?url=
/*install/index.php?lng=../../include/main.inc&G_PATH=
/*mwchat/libs/start_lobby.php?CONFIG[MWCHAT_Libs]=
/*pivot/modules/module_db.php?pivot_path=
/*support/mailling/maillist/inc/initdb.php?absolute_path=
/*zentrack/index.php?configFile=
/.gov.br/index.php?arquivo=
/?mosConfig_absolute_path=
/?p=
/?pag=
/?page=
/?pg=
/access/login.php?path_to_root=
/account.php?action=
/accounts.php?command=
/active/components/xmlrpc/client.php?c[components]
/addpost_newpoll.php?addpoll=preview&thispath=
/admin.php?cal_dir=
/admin.php?page=
/admin/auth.php?xcart_dir=
/admin/doeditconfig.php?thispath=../includes&config[path]=
/admin/inc/change_action.php?format_menue=
/admin/include/header.php?repertoire=
/admin/index.php?o=
/admincp/auth/checklogin.php?cfgProgDir=
/administrator/components/com_***ring/admin.***ring.docs.php?component_dir=
/administrator/components/com_a6mambocredits/admin.a6mambocredits.php?mosConfig_live_site=
/administrator/components/com_comprofiler/plugin.class.php?mosConfig_absolute_path=
/administrator/components/com_cropimage/admin.cropcanvas.php?cropimagedir=
/administrator/components/com_jcs/jcs.function.php?mosConfig_absolute_path=
/administrator/components/com_jcs/view/register.php?mosConfig_absolute_path=
/administrator/components/com_joom12pic/admin.joom12pic.php?mosConfig_live_site=
/administrator/components/com_joomlaradiov5/admin.joomlaradiov5.php?mosConfig_live_site=
/administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php?mosConfig_absolute_path=
/administrator/components/com_mgm/help.mgm.php?mosConfig_absolute_path=
/administrator/components/com_peoplebook/param.peoplebook.php?mosConfig_absolute_path=
/administrator/components/com_remository/admin.remository.php?mosConfig_absolute_path=
/administrator/components/com_serverstat/install.serverstat.php?mosConfig_absolute_path=
/administrator/components/com_uhp/uhp_config.php?mosConfig_absolute_path=
/admin_modules/admin_module_deldir.inc.php?config[path_src_include]=
/afb-3-beta-2007-08-28/_includes/settings.inc.php?approot=
/agendax/addevent.inc.php?agendax_path=
/akocomments.php?mosConfig_absolute_path=
/album_portal.php?phpbb_root_path=
/all"*/newbb/print.php?forum=*topic_id=*"
/all"*/newbb_plus/*="
/all"*/news/archive.php?op=*year=*month=*"
/all"*/tsep/include/colorswitch.php?tsep_config[absPath]=*"
/all".php?****="
/all".php?a="
/all".php?abrir="
/all".php?act="
/all".php?action="
/all".php?ad="
/all".php?archive="
/all".php?area="
/all".php?article="
/all".php?b="
/all".php?back="
/all".php?base="
/all".php?basedir="
/all".php?bbs="
/all".php?board_no="
/all".php?c="
/all".php?cal_dir="
/all".php?cat="
/all".php?category="
/all".php?choice="
/all".php?class="
/all".php?club_id="
/all".php?cod.tipo="
/all".php?cod="
/all".php?conf="
/all".php?configFile="
/all".php?cont="
/all".php?corpo="
/all".php?cvsroot="
/all".php?d="
/all".php?da="
/all".php?date="
/all".php?debug="
/all".php?debut="
/all".php?default="
/all".php?destino="
/all".php?dir="
/all".php?display="
/all".php?east="
/all".php?f="
/all".php?file="
/all".php?filepath="
/all".php?file_id="
/all".php?flash="
/all".php?folder="
/all".php?for="
/all".php?form="
/all".php?formatword="
/all".php?from="
/all".php?funcao="
/all".php?function="
/all".php?f_content="
/all".php?g="
/all".php?get="
/all".php?go="
/all".php?gorumDir="
/all".php?goto="
/all".php?h="
/all".php?headline="
/all".php?i="
/all".php?inc="
/all".php?include="
/all".php?includedir="
/all".php?inter="
/all".php?itemid="
/all".php?item_id="
/all".php?j="
/all".php?join="
/all".php?jojo="
/all".php?l="
/all".php?la="
/all".php?lan="
/all".php?lang="
/all".php?lest="
/all".php?link="
/all".php?load="
/all".php?loc="
/all".php?m="
/all".php?main="
/all".php?meio.php="
/all".php?meio="
/all".php?menu="
/all".php?menuID="
/all".php?mep="
/all".php?mid="
/all".php?month="
/all".php?mostra="
/all".php?my="
/all".php?n="
/all".php?nav="
/all".php?new="
/all".php?news="
/all".php?next="
/all".php?nextpage="
/all".php?o="
/all".php?op="
/all".php?open="
/all".php?option="
/all".php?origem="
/all".php?p="
/all".php?pageurl="
/all".php?Page_ID="
/all".php?para="
/all".php?part="
/all".php?perm="
/all".php?pg="
/all".php?pid="
/all".php?place="
/all".php?play="
/all".php?plugin="
/all".php?pm_path="
/all".php?poll****="
/all".php?post="
/all".php?pr="
/all".php?prefix="
/all".php?prefixo="
/all".php?q="
/all".php?redirect="
/all".php?ref="
/all".php?refid="
/all".php?regionId="
/all".php?release="
/all".php?release_id="
/all".php?return="
/all".php?root="
/all".php?S="
/all".php?searchcode_id="
/all".php?sec="
/all".php?secao="
/all".php?sect="
/all".php?sel="
/all".php?server="
/all".php?servico="
/all".php?sg="
/all".php?shard="
/all".php?show="
/all".php?sid="
/all".php?site="
/all".php?sourcedir="
/all".php?start="
/all".php?storyid="
/all".php?str="
/all".php?subd="
/all".php?subdir="
/all".php?subject="
/all".php?sufixo="
/all".php?systempath="
/all".php?t="
/all".php?task="
/all".php?teste="
/all".php?theme_dir="
/all".php?thread_id="
/all".php?tid="
/all".php?title="
/all".php?to="
/all".php?topic_id="
/all".php?type="
/all".php?u="
/all".php?url="
/all".php?urlFrom="
/all".php?v="
/all".php?var="
/all".php?vi="
/all".php?view="
/all".php?visual="
/all".php?wPage="
/all".php?y="
/all".php?z="
/all".php?zo="
/all".php?_REQUEST=&_REQUEST[option]=com_content&_REQUEST[Itemid]=1&GLOBALS=&mosConfig_absolute_path="
/all"/include/init.inc.php?CPG_M_DIR="
/all"/includes/mx_functions_ch.php?phpbb_root_path="
/all"/modules/AllMyGuests/signin.php?_AMGconfig[cfg_serverpath]="
/alladdedit.php?root_dir=
/alladdevent.inc.php?agendax_path=
/alladmin.php?cal_dir=
/allaffich.php?base=
/allalbum_portal.php?phpbb_root_path=
/allcom_extended_registration
/allcontacts.php?cal_dir=
/allconvert-date.php?cal_dir=
/alldefault.php?page=
/alldefault/theme.php?THEME_DIR=
/alldisplayCategory.php?basepath=
/alleditor.php?root=
/allexibir.php?abre=
/allexibir.php?get=
/allexibir.php?lang=
/allexibir.php?p=
/allexibir.php?page=
/allexpanded.php?conf=
/allgrademade/index.php?page=
/allheader.php?systempath=
/allinclude.php?gorumDir=
/allindex.php?a=
/allindex.php?acao=
/allindex.php?action=
/allindex.php?b=
/allindex.php?c=
/allindex.php?cal=
/allindex.php?configFile=
/allindex.php?d=
/allindex.php?directfile=
/allindex.php?e=
/allindex.php?f=
/allindex.php?funcion=
/allindex.php?g=
/allindex.php?gorumdir=
/allindex.php?h=
/allindex.php?i=
/allindex.php?include=
/allindex.php?ir=
/allindex.php?j=
/allindex.php?k=
/allindex.php?l=
/allindex.php?ll=
/allindex.php?lng=../../include/main.inc&G_PATH=
/allindex.php?lnk=
/allindex.php?loc=
/allindex.php?lv1=
/allindex.php?m=
/allindex.php?meio.php=
/allindex.php?middle=
/allindex.php?n=
/allindex.php?o=
/allindex.php?open=
/allindex.php?p=
/allindex.php?page=
/allindex.php?pageurl=
/allindex.php?path=
/allindex.php?pg=
/allindex.php?prefix=
/allindex.php?q=
/allindex.php?r=
/allindex.php?root_PATH=
/allindex.php?s=
/allindex.php?secao=
/allindex.php?seite=
/allindex.php?server=
/allindex.php?sub2=
/allindex.php?sub=
/allindex.php?t=
/allindex.php?theme=
/allindex.php?u=
/allindex.php?v=
/allindex.php?visualizar=
/allindex.php?x=
/allindex.php?y=
/allindex.php?z=
/allindex2.php?********=
/allindex2.php?a=
/allindex2.php?acao=
/allindex2.php?b=
/allindex2.php?c=
/allindex2.php?cal=
/allindex2.php?cont=
/allindex2.php?content=
/allindex2.php?d=
/allindex2.php?directfile=
/allindex2.php?e=
/allindex2.php?f=
/allindex2.php?funcion=
/allindex2.php?g=
/allindex2.php?gorumdir=
/allindex2.php?h=
/allindex2.php?i=
/allindex2.php?j=
/allindex2.php?k=
/allindex2.php?l=
/allindex2.php?lang=
/allindex2.php?ll=
/allindex2.php?lnk=
/allindex2.php?lv1=
/allindex2.php?m=
/allindex2.php?n=
/allindex2.php?o=
/allindex2.php?p=
/allindex2.php?pag=
/allindex2.php?path=
/allindex2.php?pg=
/allindex2.php?prefix=
/allindex2.php?q=
/allindex2.php?r=
/allindex2.php?root_PATH=
/allindex2.php?s=
/allindex2.php?server=
/allindex2.php?sub2=
/allindex2.php?sub=
/allindex2.php?t=
/allindex2.php?theme=
/allindex2.php?u=
/allindex2.php?v=
/allindex2.php?x=
/allindex2.php?y=
/allindex2.php?z=
/allindex2:php?aa=
/allindex3:php?aa=
/allindex5.php?********=
/allindex5.php?****=
/allindex5.php?cat=
/allindex5.php?configFile=
/allindex5.php?cont=
/allindex5.php?content=
/allindex5.php?do=
/allindex5.php?inc=
/allindex5.php?include=
/allindex5.php?lang=
/allindex5.php?lv1=
/allindex5.php?m=
/allindex5.php?main=
/allindex5.php?open=
/allindex5.php?p=
/allindex5.php?pag=
/allindex5.php?page=
/allindex5.php?pagina=
/allindex5.php?pg=
/allindex5.php?root=
/allindex5.php?site=
/allindex5.php?visualizar=
/allindex5.php?x=
/allindex_table.php?root_dir=
/allinit.inc.php?CPG_M_DIR=
/allinit.php?HTTP_POST_VARS=
/allinitdb.php?absolute_path=
/alllib.inc.php?pm_path=
/alllib.php?root=
/allmain.php?page=
/allmain.php?x=
/allmainfile.php?MAIN_PATH=
/allmodule_db.php?pivot_path=
/allmod_mainmenu.php?mosConfig_absolute_path=
/allnew-visitor.inc.php?lvc_include_dir=
/allPackages.php?sourcedir=
/allphpshop/index.php?base_dir=
/allpipe.php?HCL_path=
/allsecure_img_render.php?p=
/allstart_lobby.php?CONFIG[MWCHAT_Libs]=
/allstep_one.php?server_inc=
/allstep_one_tables.php?server_inc=
/alltemplate.php?pagina=
/alltheme.php?THEME_DIR=
/allupgrade_album.php?GALLERY_BASEDIR=
/allview.php?root_dir=
/allviewgantt.php?root_dir=
/allvw_files.php?root_dir=
/allwrite.php?dir=
/all_functions.php?prefix
/all_functions.php?prefix=
/al_initialize.php?alpath=
/amember/plugins/payment/linkpoint/linkpoint.inc.php?config[root_dir]=
/announcements.php?phpraid_dir=
/app/***editor/login.cgi?user****=&command=simple&do=edit&password=&file=
/app/common/lib/codeBeautifier/Beautifier/Core.php?BEAUT_PATH=
/apps/apps.php?app=
/appserv/main.php?appserv_root=
/arg.php?arg=
/args.php?arg=
/arquivo.php?data=
/article.php?sid=
/articles.cgi?a=34&t=
/atom.php5?page=
/auktion.pl?menue=
/auto.php?inc=
/auto.php?page=
/avatar.php?page=
/base.php?****=
/base.php?****o=
/base.php?*[*]*=
/base.php?abre=
/base.php?adresa=
/base.php?basepath=
/base.php?base_dir=
/base.php?category=
/base.php?chapter=
/base.php?choix=
/base.php?cont=
/base.php?disp=
/base.php?doshow=
/base.php?ev=
/base.php?eval=
/base.php?f1=
/base.php?filepath=
/base.php?home=
/base.php?id=
/base.php?incl=
/base.php?include=
/base.php?ir=
/base.php?itemnav=
/base.php?k=
/base.php?ki=
/base.php?l=
/base.php?lang=
/base.php?link=
/base.php?loc=
/base.php?mid=
/base.php?middle=
/base.php?middlePart=
/base.php?module=
/base.php?numero=
/base.php?oldal=
/base.php?opcion=
/base.php?p****=
/base.php?pa=
/base.php?pag=
/base.php?page***=
/base.php?panel=
/base.php?path=
/base.php?phpbb_root_path=
/base.php?play=
/base.php?rub=
/base.php?seccion=
/base.php?second=
/base.php?seite=
/base.php?sekce=
/base.php?sivu=
/base.php?str=
/base.php?subject=
/base.php?t=
/base.php?to=
/base.php?v=
/base.php?var=
/base.php?w=
/bb_usage_stats/include/bb_usage_stats.php?phpbb_root_path=
/beacon/********/1/splash.lang.php?********Path=
/becommunity/community/index.php?pageurl=
/big.php?pathtotemplate=
/biznews.cgi?a=33&t=
/blank.php?****=
/blank.php?abre=
/blank.php?action=
/blank.php?basepath=
/blank.php?base_dir=
/blank.php?category=
/blank.php?channel=
/blank.php?corpo=
/blank.php?destino=
/blank.php?dir=
/blank.php?filepath=
/blank.php?get=
/blank.php?goFile=
/blank.php?goto=
/blank.php?h=
/blank.php?header=
/blank.php?id=
/blank.php?in=
/blank.php?incl=
/blank.php?ir=
/blank.php?itemnav=
/blank.php?j=
/blank.php?ki=
/blank.php?lang=
/blank.php?left=
/blank.php?link=
/blank.php?loader=
/blank.php?menu=
/blank.php?mod=
/blank.php?o=
/blank.php?oldal=
/blank.php?open=
/blank.php?OpenPage=
/blank.php?p****=
/blank.php?pa=
/blank.php?page=
/blank.php?pagina=
/blank.php?panel=
/blank.php?path=
/blank.php?phpbb_root_path=
/blank.php?poll****=
/blank.php?pr=
/blank.php?pre=
/blank.php?pref=
/blank.php?qry=
/blank.php?read=
/blank.php?ref=
/blank.php?rub=
/blank.php?section=
/blank.php?sivu=
/blank.php?sp=
/blank.php?strona=
/blank.php?subject=
/blank.php?t=
/blank.php?url=
/blank.php?var=
/blank.php?where=
/blank.php?xlink=
/blank.php?z=
/board.php?see=
/book.php5?page=
/bz/squito/photolist.inc.php?photoroot=
/calendar.php?l=
/calendar.php?p=
/calendar.php?pg=
/calendar.php?s=
/calendar.pl?command=login&fromTemplate=
/canal.php?meio=
/ccbill/whereami.cgi?g=ls
/cgi-bin/1/cmd.cgi
/cgi-bin/acart/acart.pl?&page=
/cgi-bin/awstats.pl?update=1&logfile=
/cgi-bin/awstats/awstats.pl?configdir
/cgi-bin/bbs/read.cgi?file=
/cgi-bin/bp/bp-lib.pl?g=
/cgi-bin/hinsts.pl?
/cgi-bin/ikonboard.cgi
/cgi-bin/index.cgi?page=
/cgi-bin/jammail.pl?job=showoldmail&mail=
/cgi-bin/probe.cgi?olddat=
/cgi-bin/quikstore.cgi?category=
/cgi-bin/telnet.cgi
/cgi-bin/ubb/ubb.cgi?g=
/cgi-sys/guestbook.cgi?user=cpanel&template=
/chat/inc/cmses/aedating4CMS.php?dir[inc]=
/claroline/inc/claro_init_header.inc.php?includePath=
/class.mysql.php?path_to_bt_dir=
/classes.php?LOCAL_PATH=
/classes/adodbt/sql.php?classes_dir=
/classes/core/********.php?rootdir=
/classified_right.php?********_dir=
/classified_right.php?language_dir=
/cmd.php?arg=
/codebb/lang_select?phpbb_root_path=
/coin_includes/constants.php?_CCFG[_PKG_PATH_INCL]=
/common/func.php?CommonAbsDir=
/components/com_artlinks/artlinks.dispnew.php?mosConfig_absolute_path=
/components/com_colorlab/admin.color.php?mosConfig_live_site=
/components/com_cpg/cpg.php?mosConfig_absolute_path=
/components/com_extcalendar/admin_events.php?CONFIG_EXT[********S_DIR]=
/components/com_extended_registration/registration_detailed.inc.php?mosConfig_absolute_path=
/components/com_facileforms/facileforms.frame.php?ff_compath=
/components/com_forum/download.php?phpbb_root_path=
/components/com_galleria/galleria.html.php?mosConfig_absolute_path=
/components/com_mp3_allopass/allopass-error.php?mosConfig_live_site=
/components/com_mp3_allopass/allopass.php?mosConfig_live_site=
/components/com_mtree/Savant2/Savant2_Plugin_****area.php?mosConfig_absolute_path=
/components/com_mtree/Savant2/Savant2_Plugin_stylesheet.php?mosConfig_absolute_path=
/components/com_mtree/Savant2/Savant2_Plugin_textarea.php?mosConfig_absolute_path=
/components/com_performs/performs.php?mosConfig_absolute_path=
/components/com_phpshop/toolbar.phpshop.html.php?mosConfig_absolute_path=
/components/com_rsgallery/rsgallery.html.php?mosConfig_absolute_path=
/components/com_simpleboard/image_upload.php?sbp=
/components/com_smf/smf.php?mosConfig_absolute_path=
/components/com_zoom/includes/database.php?mosConfig_absolute_path=
/config.inc.php?path_escape=
/config.inc.php?_path=
/config.php?fpath=
/config.php?path_to_root=
/config.php?xcart_dir=
/contacts.php?cal_dir=
/contenido.php?sec=
/contenido/classes/class.inuse.php
/content.php?inc=
/content.php?page=
/content.php?seite=
/content/article.php?ide=
/content/modify_go.php?pwfile=
/contrib/mx_glance_sdesc.php?mx_root_path=
/contrib/yabbse/poc.php?poc_root_path=
/convert-date.php?cal_dir=
/convert/mvcw.php?step=1&vwar_root=
/convert/mvcw.php?vwar_root=
/coppercop/theme.php?THEME_DIR=
/csv_db/csv_db.cgi?fil
/customer/product.php?xcart_dir=
/cyberfolio/portfolio/msg/view.php?av=
/data/compatible.php?module_****=
/database.php?mosConfig_absolute_path=
/db.php?path_local=
/dbase.php?action=
/dbmodules/DB_adodb.class.php?PHPOF_INCLUDE_PATH=
/Decoder.php?base_dir=
/default.php?****=
/default.php?*root*=
/default.php?abre=
/default.php?arquivo=
/default.php?basepath=
/default.php?base_dir=
/default.php?channel=
/default.php?chapter=
/default.php?choix=
/default.php?cmd=
/default.php?cont=
/default.php?destino=
/default.php?e=
/default.php?eval=
/default.php?f=
/default.php?goto=
/default.php?header=
/default.php?id=
/default.php?inc=
/default.php?incl=
/default.php?include=
/default.php?index=
/default.php?ir=
/default.php?itemnav=
/default.php?k=
/default.php?ki=
/default.php?l=
/default.php?left=
/default.php?load=
/default.php?loader=
/default.php?loc=
/default.php?m=
/default.php?menu=
/default.php?menue=
/default.php?mid=
/default.php?mod=
/default.php?module=
/default.php?n=
/default.php?nivel=
/default.php?oldal=
/default.php?opcion=
/default.php?option=
/default.php?p=
/default.php?pa=
/default.php?pag=
/default.php?page***=
/default.php?page=
/default.php?page=home
/default.php?panel=
/default.php?param=
/default.php?play=
/default.php?pr=
/default.php?pre=
/default.php?read=
/default.php?ref=
/default.php?rub=
/default.php?secao=
/default.php?secc=
/default.php?seccion=
/default.php?seite=
/default.php?showpage=
/default.php?sivu=
/default.php?sp=
/default.php?str=
/default.php?strona=
/default.php?t=
/default.php?thispage=
/default.php?tipo=
/default.php?to=
/default.php?type=
/default.php?v=
/default.php?var=
/default.php?vis=
/default.php?x=
/default.php?y=
/define.php?term=
/deportes.cgi?a=latest&t=
/detail.php?prod=
/details.php?loc=
/dfd_cart/app.lib/product.control/core.php/customer.area/customer.browse.list.php?set_depth=
/dfd_cart/app.lib/product.control/core.php/customer.area/customer.browse.search.php?set_depth=
/dfd_cart/app.lib/product.control/core.php/product.control.config.php?set_depth=
/direct.php?loc=
/directions.php?loc=
/display.php?f=
/display.php?file=
/display.php?l=
/display.php?lang=
/display.php?ln=
/display.php?p=
/display.php?pag=
/display.php?page=
/display.php?page=&lang=
/display.php?pg=
/display.php?s=
/display.php?table=
/dotproject/modules/files/index_table.php?root_dir=
/dotproject/modules/projects/addedit.php?root_dir=
/dotproject/modules/projects/view.php?root_dir=
/dotproject/modules/projects/vw_files.php?root_dir=
/dotproject/modules/tasks/addedit.php?root_dir=
/dotproject/modules/tasks/viewgantt.php?root_dir=
/down*.php?****o=
/down*.php?action=
/down*.php?addr=
/down*.php?channel=
/down*.php?choix=
/down*.php?cmd=
/down*.php?corpo=
/down*.php?disp=
/down*.php?doshow=
/down*.php?ev=
/down*.php?filepath=
/down*.php?goFile=
/down*.php?home=
/down*.php?in=
/down*.php?inc=
/down*.php?incl=
/down*.php?include=
/down*.php?ir=
/down*.php?lang=
/down*.php?left=
/down*.php?nivel=
/down*.php?oldal=
/down*.php?open=
/down*.php?OpenPage=
/down*.php?pa=
/down*.php?pag=
/down*.php?page***=
/down*.php?param=
/down*.php?path=
/down*.php?pg=
/down*.php?phpbb_root_path=
/down*.php?poll****=
/down*.php?pr=
/down*.php?pre=
/down*.php?qry=
/down*.php?r=
/down*.php?read=
/down*.php?s=
/down*.php?second=
/down*.php?section=
/down*.php?seite=
/down*.php?showpage=
/down*.php?sp=
/down*.php?strona=
/down*.php?subject=
/down*.php?t=
/down*.php?to=
/down*.php?u=
/down*.php?url=
/down*.php?v=
/down*.php?where=
/down*.php?x=
/down*.php?z=
/download.php?sub=
/drupal/?_menu[callbacks][1][callback]=
/e107/e107_handlers/secure_img_render.php?p=
/embed/day.php?path=
/emsgb/easymsgb.pl?print=
/enc/content.php?Home_Path=
/encapscms_PATH/core/core.php?root=
/Encoder.php?base_dir=
/encore/forumcgi/display.cgi?preftemp=temp&page=anonymous&file=
/eng.php?img=
/enter.php?****=
/enter.php?****o=
/enter.php?a=
/enter.php?abre=
/enter.php?addr=
/enter.php?b=
/enter.php?base_dir=
/enter.php?chapter=
/enter.php?cmd=
/enter.php?content=
/enter.php?e=
/enter.php?ev=
/enter.php?get=
/enter.php?go=
/enter.php?goto=
/enter.php?home=
/enter.php?id=
/enter.php?incl=
/enter.php?include=
/enter.php?index=
/enter.php?ir=
/enter.php?itemnav=
/enter.php?lang=
/enter.php?left=
/enter.php?link=
/enter.php?loader=
/enter.php?menue=
/enter.php?mid=
/enter.php?middle=
/enter.php?mod=
/enter.php?module=
/enter.php?numero=
/enter.php?open=
/enter.php?p****=
/enter.php?pa=
/enter.php?page=
/enter.php?pagina=
/enter.php?panel=
/enter.php?path=
/enter.php?pg=
/enter.php?phpbb_root_path=
/enter.php?play=
/enter.php?pr=
/enter.php?pref=
/enter.php?qry=
/enter.php?r=
/enter.php?read=
/enter.php?ref=
/enter.php?s=
/enter.php?sec=
/enter.php?second=
/enter.php?seite=
/enter.php?sivu=
/enter.php?sp=
/enter.php?start=
/enter.php?str=
/enter.php?strona=
/enter.php?subject=
/enter.php?thispage=
/enter.php?type=
/enter.php?viewpage=
/enter.php?w=
/enter.php?y=
/environment.php?DIR_PREFIX=
/esupport/admin/autoclose.php?subd=
/es_custom_menu.php?files_dir=
/es_desp.php?files_dir=
/es_offer.php?files_dir=
/etc/certs + "index of /" */*
/etc/config + "index of /" /
/events.cgi?a=155&t=
/events.cgi?t=
/exibir.php?arquivo=
/experts.php?sub=
/extensions/moblog/moblog_lib.php?basedir=
/extras/ext_cats.php?dir_path=
/file.php?****=
/file.php?****o=
/file.php?action=
/file.php?basepath=
/file.php?channel=
/file.php?chapter=
/file.php?choix=
/file.php?cmd=
/file.php?cont=
/file.php?corpo=
/file.php?disp=
/file.php?doshow=
/file.php?ev=
/file.php?eval=
/file.php?get=
/file.php?id=
/file.php?inc=
/file.php?incl=
/file.php?include=
/file.php?index=
/file.php?ir=
/file.php?ki=
/file.php?left=
/file.php?load=
/file.php?loader=
/file.php?middle=
/file.php?modo=
/file.php?n=
/file.php?nivel=
/file.php?numero=
/file.php?oldal=
/file.php?pagina=
/file.php?param=
/file.php?pg=
/file.php?play=
/file.php?poll****=
/file.php?pref=
/file.php?q=
/file.php?qry=
/file.php?ref=
/file.php?seccion=
/file.php?second=
/file.php?showpage=
/file.php?sivu=
/file.php?sp=
/file.php?start=
/file.php?strona=
/file.php?to=
/file.php?type=
/file.php?url=
/file.php?var=
/file.php?viewpage=
/file.php?where=
/file.php?y=
/fileseek.cgi?head=&foot=
/folder.php?id=
/forum.php?act=
/forum.php?seite=
/forum/forum.php?view=
/frag.php?exec=
/frame.php?loc=
/functions.php?include_path=
/galerie.php?do=
/gallery.php?****=
/gallery.php?*[*]*=
/gallery.php?abre=
/gallery.php?action=
/gallery.php?addr=
/gallery.php?basepath=
/gallery.php?base_dir=
/gallery.php?chapter=
/gallery.php?cont=
/gallery.php?corpo=
/gallery.php?disp=
/gallery.php?ev=
/gallery.php?eval=
/gallery.php?filepath=
/gallery.php?get=
/gallery.php?go=
/gallery.php?h=
/gallery.php?id=
/gallery.php?index=
/gallery.php?itemnav=
/gallery.php?ki=
/gallery.php?left=
/gallery.php?loader=
/gallery.php?menu=
/gallery.php?menue=
/gallery.php?mid=
/gallery.php?mod=
/gallery.php?module=
/gallery.php?my=
/gallery.php?nivel=
/gallery.php?oldal=
/gallery.php?open=
/gallery.php?option=
/gallery.php?p****=
/gallery.php?pag=
/gallery.php?page***=
/gallery.php?page=
/gallery.php?panel=
/gallery.php?param=
/gallery.php?pg=
/gallery.php?phpbb_root_path=
/gallery.php?poll****=
/gallery.php?pre=
/gallery.php?pref=
/gallery.php?qry=
/gallery.php?redirect=
/gallery.php?ref=
/gallery.php?rub=
/gallery.php?sec=
/gallery.php?secao=
/gallery.php?seccion=
/gallery.php?seite=
/gallery.php?showpage=
/gallery.php?sivu=
/gallery.php?sp=
/gallery.php?strona=
/gallery.php?thispage=
/gallery.php?tipo=
/gallery.php?to=
/gallery.php?url=
/gallery.php?var=
/gallery.php?viewpage=
/gallery.php?where=
/gallery.php?xlink=
/gallery.php?y=
/gallery/init.php?HTTP_POST_VARS=
/general.php?****=
/general.php?****o=
/general.php?abre=
/general.php?addr=
/general.php?adresa=
/general.php?b=
/general.php?base_dir=
/general.php?channel=
/general.php?chapter=
/general.php?choix=
/general.php?cmd=
/general.php?content=
/general.php?doshow=
/general.php?e=
/general.php?f=
/general.php?get=
/general.php?goto=
/general.php?header=
/general.php?id=
/general.php?inc=
/general.php?include=
/general.php?ir=
/general.php?itemnav=
/general.php?left=
/general.php?link=
/general.php?menu=
/general.php?menue=
/general.php?mid=
/general.php?middle=
/general.php?modo=
/general.php?module=
/general.php?my=
/general.php?nivel=
/general.php?opcion=
/general.php?p=
/general.php?page***=
/general.php?page=
/general.php?poll****=
/general.php?pr=
/general.php?pre=
/general.php?qry=
/general.php?read=
/general.php?redirect=
/general.php?ref=
/general.php?rub=
/general.php?secao=
/general.php?seccion=
/general.php?second=
/general.php?section=
/general.php?seite=
/general.php?sekce=
/general.php?sivu=
/general.php?strona=
/general.php?subject=
/general.php?thispage=
/general.php?tipo=
/general.php?to=
/general.php?type=
/general.php?var=
/general.php?w=
/general.php?where=
/general.php?xlink=
/glossary.php?term=
/GradeMap/index.php?page=
/hall.php?file=
/hall.php?page=
/handlinger.php?vis=
/head.php?*[*]*=
/head.php?abre=
/head.php?adresa=
/head.php?b=
/head.php?base_dir=
/head.php?c=
/head.php?choix=
/head.php?cmd=
/head.php?content=
/head.php?corpo=
/head.php?d=
/head.php?dir=
/head.php?disp=
/head.php?ev=
/head.php?filepath=
/head.php?g=
/head.php?goto=
/head.php?inc=
/head.php?incl=
/head.php?include=
/head.php?index=
/head.php?ir=
/head.php?ki=
/head.php?lang=
/head.php?left=
/head.php?load=
/head.php?loader=
/head.php?loc=
/head.php?middle=
/head.php?middlePart=
/head.php?mod=
/head.php?modo=
/head.php?module=
/head.php?numero=
/head.php?oldal=
/head.php?opcion=
/head.php?p****=
/head.php?pag=
/head.php?page***=
/head.php?play=
/head.php?poll****=
/head.php?read=
/head.php?ref=
/head.php?rub=
/head.php?sec=
/head.php?sekce=
/head.php?sivu=
/head.php?start=
/head.php?str=
/head.php?strona=
/head.php?tipo=
/head.php?viewpage=
/head.php?where=
/head.php?y=
/header.php?abspath=
/help.php?css_path=
/help_****_vars.php?cmd=dir&PGV_BASE_DIRECTORY=
/historytemplate.php?cms[support]=1&cms[tngpath]=
/home.php?****=
/home.php?a=
/home.php?act=
/home.php?action=
/home.php?addr=
/home.php?arg=
/home.php?basepath=
/home.php?base_dir=
/home.php?category=
/home.php?channel=
/home.php?chapter=
/home.php?choix=
/home.php?cmd=
/home.php?content=
/home.php?disp=
/home.php?doshow=
/home.php?e=
/home.php?ev=
/home.php?eval=
/home.php?func=
/home.php?g=
/home.php?h=
/home.php?i=
/home.php?in=
/home.php?inc=
/home.php?include=
/home.php?index=
/home.php?ir=
/home.php?itemnav=
/home.php?k=
/home.php?link=
/home.php?ln=
/home.php?loader=
/home.php?loc=
/home.php?ltr=
/home.php?menu=
/home.php?middle=
/home.php?middlePart=
/home.php?module=
/home.php?my=
/home.php?oldal=
/home.php?opcion=
/home.php?pa=
/home.php?pag=
/home.php?page***=
/home.php?page=
/home.php?pagina=
/home.php?panel=
/home.php?path=
/home.php?play=
/home.php?poll****=
/home.php?pr=
/home.php?pre=
/home.php?qry=
/home.php?read=
/home.php?recipe=
/home.php?redirect=
/home.php?ref=
/home.php?rub=
/home.php?sec=
/home.php?secao=
/home.php?section=
/home.php?seite=
/home.php?sekce=
/home.php?showpage=
/home.php?sit=
/home.php?sp=
/home.php?str=
/home.php?table=
/home.php?thispage=
/home.php?tipo=
/home.php?w=
/home.php?where=
/home.php?x=
/home.php?z=
/home1.php?ln=
/home2.php?ln=
/homepage.php?sel=
/html/affich.php?base=
/htmltonuke.php?filnavn=
/i-mall/i-mall.cgi?p=
/ideabox/include.php?gorumDir=
/ihm.php?p=
/image.php?img=
/images/evil.php?owned=
/img.php?loc=
/impex/ImpExData.php?systempath=
/inc.php?inc=
/inc/cmses/aedating4CMS.php?dir[inc]=
/inc/cmses/aedatingCMS.php?dir[inc]=
/inc/functions.inc.php?config[ppa_root_path]=
/inc/header.php/step_one.php?server_inc=
/inc/irayofuncs.php?irayodirhack=
/inc/pipe.php?HCL_path=
/inc/session.php?sessionerror=0&lang=
/inc/step_one_tables.php?server_inc=
/include.php?****=
/include.php?*[*]*=
/include.php?adresa=
/include.php?b=
/include.php?basepath=
/include.php?channel=
/include.php?chapter=
/include.php?cmd=
/include.php?cont=
/include.php?content=
/include.php?corpo=
/include.php?destino=
/include.php?dir=
/include.php?eval=
/include.php?filepath=
/include.php?go=
/include.php?goFile=
/include.php?goto=
/include.php?header=
/include.php?in=
/include.php?include=
/include.php?index=
/include.php?ir=
/include.php?ki=
/include.php?left=
/include.php?loader=
/include.php?loc=
/include.php?mid=
/include.php?middle=
/include.php?middlePart=
/include.php?module=
/include.php?my=
/include.php?nivel=
/include.php?numero=
/include.php?oldal=
/include.php?option=
/include.php?pag=
/include.php?page***=
/include.php?panel=
/include.php?path=
/include.php?path[docroot]=
/include.php?phpbb_root_path=
/include.php?play=
/include.php?read=
/include.php?redirect=
/include.php?ref=
/include.php?sec=
/include.php?secao=
/include.php?seccion=
/include.php?second=
/include.php?sivu=
/include.php?tipo=
/include.php?to=
/include.php?u=
/include.php?url=
/include.php?w=
/include.php?x=
/include/editfunc.inc.php?NWCONF_SYSTEM[server_path]=
/include/footer.inc.php?_AMLconfig[cfg_serverpath]=
/include/main.php?config[search_disp]=true&include_dir=
/include/new-visitor.inc.php?lvc_include_dir=
/include/write.php?dir=
/includes/archive/archive_topic.php?phpbb_root_path=
/includes/dbal.php?eqdkp_root_path=
/includes/functions.php?phpbb_root_path=
/includes/functions_portal.php?phpbb_root_path=
/includes/header.php?systempath=
/includes/kb_constants.php?module_root_path=
/includes/lang/********.php?path_to_root=
/includes/openid/Auth/OpenID/BBStore.php?openid_root_path=
/includes/orderSuccess.inc.php?glob=1&cart_order_id=1&glob[rootDir]=
/includes/search.php?GlobalSettings[templatesDirectory]=
/index.php3?act=
/index.php3?file=
/index.php3?i=
/index.php3?id=
/index.php3?l=
/index.php3?lang=
/index.php3?p=
/index.php3?pag=
/index.php3?page=
/index.php3?pg=
/index.php3?s=
/index.php4?lang=
/index.php5?lang=
/index.php?********=
/index.php?****=
/index.php?****field=
/index.php?a=
/index.php?acao=
/index.php?act=
/index.php?action=
/index.php?addr=
/index.php?adresa=
/index.php?arg=
/index.php?arq=
/index.php?arquivo=
/index.php?b=
/index.php?ba=
/index.php?bas=
/index.php?base=
/index.php?basepath=
/index.php?base_dir=
/index.php?c=
/index.php?cal=
/index.php?canal=
/index.php?cat=
/index.php?channel=
/index.php?chapter=
/index.php?classified_path=
/index.php?cmd=
/index.php?cms=
/index.php?command=
/index.php?configFile=
/index.php?cont=
/index.php?content=
/index.php?conteudo=
/index.php?d1=
/index.php?def=
/index.php?dept=
/index.php?disp=
/index.php?dn=
/index.php?do=
/index.php?doc=
/index.php?dok=
/index.php?dsp=
/index.php?e=
/index.php?ev=
/index.php?exec=
/index.php?f1=
/index.php?f=
/index.php?fase=
/index.php?file=
/index.php?filepath=
/index.php?fn=
/index.php?fPage=
/index.php?fset=
/index.php?func=
/index.php?function=custom&custom=
/index.php?go1=
/index.php?go=
/index.php?goto=
/index.php?hl=
/Index.php?id=
/index.php?id=
/index.php?id=&lang=
/index.php?id=&page=
/index.php?id=1&lang=
/index.php?inc=
/index.php?incl=
/index.php?include=
/index.php?index=
/index.php?inhalt=
/index.php?ir=
/index.php?j=
/index.php?kobr=
/index.php?l=
/index.php?lang=
/index.php?lang=&page=
/index.php?lang=en&cat=
/index.php?lang=en&page=
/index.php?lang=gr&file
/index.php?langc=
/index.php?lg=
/index.php?link=
/index.php?lk=
/index.php?ln=
/index.php?lng=
/index.php?lnk=
/index.php?Load=
/index.php?load=
/index.php?loc=
/index.php?loc=&cat=
/index.php?loc=&lang=
/index.php?loc=&page=
/index.php?loc=start&page=
/index.php?loca=
/index.php?ltr=
/index.php?m=
/index.php?main=
/index.php?meio.php=
/index.php?meio=
/index.php?menu=
/index.php?menu=deti&page=
/index.php?mf=
/index.php?mid=
/index.php?middle=
/index.php?middlePart=
/index.php?mn=
/index.php?mod=
/index.php?mode=
/index.php?modo=
/index.php?module=
/index.php?new=
/index.php?news=
/index.php?nic=
/index.php?oldal=
/index.php?op=
/index.php?opcao=
/index.php?opcion=
/index.php?open=
/index.php?openfile=
/index.php?option=
/index.php?ort=
/index.php?p****=
/index.php?p=
/index.php?pag=
/index.php?page****=
/index.php?page1=
/index.php?page=
/index.php?page=&lang=
/index.php?pageN=
/index.php?pager=
/index.php?pageurl=
/index.php?pagina1=
/index.php?pagina=
/index.php?param=
/index.php?path=
/index.php?pg=
/index.php?pg_ID=
/index.php?pilih=
/index.php?place=
/index.php?play=
/index.php?plugin=
/index.php?poll****=
/index.php?pr=
/index.php?pre=
/index.php?pref=
/index.php?principal=
/index.php?prod=
/index.php?product=
/index.php?r=
/index.php?rage=
/index.php?recipe=
/index.php?redir=
/index.php?root_path=
/index.php?RP_PATH=
/index.php?s=
/index.php?screen=
/index.php?sec=
/index.php?secao=
/index.php?seccion=
/index.php?seite=
/index.php?sekce=
/index.php?sel=
/index.php?select=
/index.php?set=
/index.php?sf=
/index.php?show=
/index.php?side=
/index.php?sit=
/index.php?site1=
/index.php?site=
/index.php?sivu=
/index.php?skin_file=
/index.php?slang=
/index.php?sort=
/index.php?spage=
/index.php?ss=
/index.php?st=
/index.php?str=
/index.php?stranica=
/index.php?strona=
/index.php?sub=
/index.php?subp=
/index.php?subpage=
/index.php?t=
/index.php?table=
/index.php?task=
/index.php?template=
/index.php?templateid=
/index.php?term=
/index.php?theme=
/index.php?themesdir=
/index.php?tipo=
/index.php?to=
/index.php?topic=
/index.php?trans=
/index.php?type=
/index.php?u=
/index.php?url=
/index.php?v=
/index.php?var1=
/index.php?var2=
/index.php?var=
/index.php?ver=
/index.php?vis=
/index.php?visualizar=
/index.php?vpagina=
/index.php?w=
/index.php?way=
/index.php?where=
/index.php?wpage=
/index.php?x=
/index.php?y=
/index.php?_REQUEST=&_REQUEST%5boption%5d=com_content&_REQUEST%5bItemid%5d=1&GLOBALS=&mosConfig_absolute_path=
/index.php?_REQUEST=&_REQUEST[option]=com_content&_REQUEST[Itemid]=1&GLOBALS=&mosConfig_absolute_path=
/index.phpmain.php?x=
/index0.php?show=
/index1.php?****=
/index1.php?****o=
/index1.php?*root*=
/index1.php?*[*]*=
/index1.php?=
/index1.php?abre=
/index1.php?action=
/index1.php?adresa=
/index1.php?arg=
/index1.php?arq=
/index1.php?b=
/index1.php?c=
/index1.php?chapter=
/index1.php?choix=
/index1.php?cmd=
/index1.php?d=
/index1.php?dat=
/index1.php?dir=
/index1.php?filepath=
/index1.php?func=
/index1.php?get=
/index1.php?go=
/index1.php?goFile=
/index1.php?home=
/index1.php?inc=
/index1.php?incl=
/index1.php?itemnav=
/index1.php?l=
/index1.php?link=
/index1.php?lk=
/index1.php?ln=
/index1.php?load=
/index1.php?loc=
/index1.php?ltr=
/index1.php?menu=
/index1.php?mid=
/index1.php?mod=
/index1.php?modo=
/index1.php?my=
/index1.php?nivel=
/index1.php?o=
/index1.php?oldal=
/index1.php?op=
/index1.php?OpenPage=
/index1.php?p****=
/index1.php?p=
/index1.php?pa=
/index1.php?page=
/index1.php?pagina=
/index1.php?param=
/index1.php?path=
/index1.php?pg=
/index1.php?poll****=
/index1.php?pr=
/index1.php?pre=
/index1.php?qry=
/index1.php?read=
/index1.php?recipe=
/index1.php?redirect=
/index1.php?s=
/index1.php?second=
/index1.php?seite=
/index1.php?sekce=
/index1.php?show=
/index1.php?showpage=
/index1.php?site=
/index1.php?str=
/index1.php?strona=
/index1.php?subject=
/index1.php?t=
/index1.php?table=
/index1.php?tipo=
/index1.php?type=
/index1.php?url=
/index1.php?v=
/index1.php?var=
/index1.php?x=
/index2.php?****o=
/index2.php?=
/index2.php?action=
/index2.php?adresa=
/index2.php?arg=
/index2.php?arq=
/index2.php?ascii_seite=
/index2.php?basepath=
/index2.php?base_dir=
/index2.php?c=
/index2.php?category=
/index2.php?channel=
/index2.php?chapter=
/index2.php?choix=
/index2.php?cmd=
/index2.php?cont=
/index2.php?content=
/index2.php?corpo=
/index2.php?d=
/index2.php?DoAction=
/index2.php?doshow=
/index2.php?e=
/index2.php?f=
/index2.php?filepath=
/index2.php?get=
/index2.php?goto=
/index2.php?home=
/index2.php?i=
/index2.php?ID=
/index2.php?in=
/index2.php?inc=
/index2.php?incl=
/index2.php?include=
/index2.php?ir=
/index2.php?itemnav=
/index2.php?ki=
/index2.php?l=
/index2.php?left=
/index2.php?lg=
/index2.php?link=
/index2.php?lk=
/index2.php?ln=
/index2.php?lng=
/index2.php?load=
/index2.php?loader=
/index2.php?loc=
/index2.php?loca=
/index2.php?meio=
/index2.php?module=
/index2.php?my=
/index2.php?oldal=
/index2.php?open=
/index2.php?OpenPage=
/index2.php?option=
/index2.php?p****=
/index2.php?p=
/index2.php?pa=
/index2.php?pag=
/index2.php?param=
/index2.php?pg=
/index2.php?phpbb_root_path=
/index2.php?poll****=
/index2.php?pre=
/index2.php?pref=
/index2.php?qry=
/index2.php?recipe=
/index2.php?redirect=
/index2.php?ref=
/index2.php?rub=
/index2.php?s=
/index2.php?second=
/index2.php?section=
/index2.php?sekce=
/index2.php?showpage=
/index2.php?strona=
/index2.php?table=
/index2.php?thispage=
/index2.php?to=
/index2.php?type=
/index2.php?u=
/index2.php?url_page=
/index2.php?var=
/index2.php?x=
/index3.php?****=
/index3.php?abre=
/index3.php?addr=
/index3.php?adresa=
/index3.php?base_dir=
/index3.php?channel=
/index3.php?chapter=
/index3.php?choix=
/index3.php?cmd=
/index3.php?d=
/index3.php?destino=
/index3.php?dir=
/index3.php?disp=
/index3.php?ev=
/index3.php?get=
/index3.php?go=
/index3.php?home=
/index3.php?inc=
/index3.php?include=
/index3.php?index=
/index3.php?ir=
/index3.php?itemnav=
/index3.php?left=
/index3.php?link=
/index3.php?loader=
/index3.php?menue=
/index3.php?mid=
/index3.php?middle=
/index3.php?mod=
/index3.php?my=
/index3.php?nivel=
/index3.php?oldal=
/index3.php?open=
/index3.php?option=
/index3.php?p****=
/index3.php?p=
/index3.php?pag=
/index3.php?page***=
/index3.php?panel=
/index3.php?path=
/index3.php?phpbb_root_path=
/index3.php?poll****=
/index3.php?pre=
/index3.php?pref=
/index3.php?q=
/index3.php?read=
/index3.php?redirect=
/index3.php?ref=
/index3.php?rub=
/index3.php?secao=
/index3.php?secc=
/index3.php?seccion=
/index3.php?second=
/index3.php?sekce=
/index3.php?showpage=
/index3.php?sivu=
/index3.php?sp=
/index3.php?start=
/index3.php?t=
/index3.php?thispage=
/index3.php?tipo=
/index3.php?type=
/index3.php?url=
/index3.php?var=
/index3.php?x=
/index3.php?xlink=
/index_principal.php?pagina=
/info.php?****=
/info.php?****o=
/info.php?*[*]*=
/info.php?adresa=
/info.php?base_dir=
/info.php?c=
/info.php?chapter=
/info.php?content=
/info.php?doshow=
/info.php?ev=
/info.php?eval=
/info.php?f=
/info.php?filepath=
/info.php?go=
/info.php?header=
/info.php?home=
/info.php?in=
/info.php?incl=
/info.php?ir=
/info.php?itemnav=
/info.php?j=
/info.php?ki=
/info.php?l=
/info.php?ln=
/info.php?loader=
/info.php?menue=
/info.php?mid=
/info.php?middlePart=
/info.php?o=
/info.php?oldal=
/info.php?op=
/info.php?opcion=
/info.php?option=
/info.php?p****=
/info.php?page***=
/info.php?pagina=
/info.php?param=
/info.php?phpbb_root_path=
/info.php?pref=
/info.php?r=
/info.php?read=
/info.php?recipe=
/info.php?redirect=
/info.php?ref=
/info.php?rub=
/info.php?sec=
/info.php?secao=
/info.php?seccion=
/info.php?start=
/info.php?strona=
/info.php?subject=
/info.php?t=
/info.php?url=
/info.php?var=
/info.php?xlink=
/info.php?z=
/install/index.php?lng=../../include/main.inc&G_PATH=
/intern/admin/?rootdir=
/intern/admin/other/backup.php?admin=1&rootdir=
/intern/clan/member_add.php?rootdir=
/intern/config/forum.php?rootdir=
/intern/config/key_2.php?rootdir=
/interna.php?meio=
/interna/tiny_mce/plugins/ibrowser/ibrowser.php?tinyMCE_imglib_include=
/jobs.cgi?a=9&t=
/joomla/index.php?option=com_restaurante&task=
/jscript.php?my_ms[root]=
/kalender.php?vis=
/lang.php?arg=
/lang.php?arq=
/lang.php?lk=
/lang.php?ln=
/lang.php?subp=
/lang.php?subpage=
/latinbitz.cgi?t=
/layout.php?abre=
/layout.php?action=
/layout.php?addr=
/layout.php?basepath=
/layout.php?c=
/layout.php?category=
/layout.php?chapter=
/layout.php?choix=
/layout.php?cmd=
/layout.php?cont=
/layout.php?disp=
/layout.php?g=
/layout.php?goto=
/layout.php?incl=
/layout.php?ir=
/layout.php?link=
/layout.php?loader=
/layout.php?menue=
/layout.php?modo=
/layout.php?my=
/layout.php?nivel=
/layout.php?numero=
/layout.php?oldal=
/layout.php?opcion=
/layout.php?OpenPage=
/layout.php?page***=
/layout.php?page=
/layout.php?pagina=
/layout.php?panel=
/layout.php?path=
/layout.php?play=
/layout.php?poll****=
/layout.php?pref=
/layout.php?qry=
/layout.php?secao=
/layout.php?section=
/layout.php?seite=
/layout.php?sekce=
/layout.php?strona=
/layout.php?thispage=
/layout.php?tipo=
/layout.php?url=
/layout.php?var=
/layout.php?where=
/layout.php?xlink=
/layout.php?z=
/lc.cgi?a=
/lib/base.php?BaseCfg[BaseDir]=
/lib/db/ez_sql.php?lib_path=
/lib/functions.php?DOC_ROOT=
/lib/gore.php?libpath=
/lib/header.php?DOC_ROOT=
/lib/static/header.php?set_menu=
/library/editor/editor.php?root=
/library/lib.php?root=
/link.php?do=
/list.php?product=
/list.php?table=
/llindex.php?sub=
/ln.php?ln=
/loc.php?l=
/loc.php?lang=
/loc.php?loc=
/login.php?dir=
/login.php?loca=
/m2f/m2f_phpbb204.php?m2f_root_path=
/magazine.php?inc=
/mai.php?act=
/mai.php?loc=
/mai.php?src=
/main.html.php?seite=
/main.php3?act=
/main.php5?page=
/main.php?****=
/main.php?a=
/main.php?action=
/main.php?addr=
/main.php?adresa=
/main.php?arg=
/main.php?ba=
/main.php?basepath=
/main.php?category=
/main.php?chapter=
/main.php?command=
/main.php?content=
/main.php?corpo=
/main.php?d1=
/main.php?dir=
/main.php?disp=
/main.php?doshow=
/main.php?e=
/main.php?eval=
/main.php?f1=
/main.php?filepath=
/main.php?fset=
/main.php?goto=
/main.php?h=
/main.php?id=
/main.php?inc=
/main.php?include=
/main.php?index=
/main.php?ir=
/main.php?itemnav=
/main.php?j=
/main.php?link=
/main.php?ln=
/main.php?load=
/main.php?loc=
/main.php?ltr=
/main.php?middle=
/main.php?mod=
/main.php?my=
/main.php?oldal=
/main.php?opcion=
/main.php?p****=
/main.php?page=
/main.php?pagina=
/main.php?param=
/main.php?path=
/main.php?pg=
/main.php?pre=
/main.php?pref=
/main.php?r=
/main.php?ref=
/main.php?s=
/main.php?sayfa=
/main.php?second=
/main.php?section=
/main.php?sit=
/main.php?site=
/main.php?start=
/main.php?str=
/main.php?strona=
/main.php?subject=
/main.php?table=
/main.php?thispage=
/main.php?tipo=
/main.php?type=
/main.php?url=
/main.php?v=
/main.php?vis=
/main.php?where=
/main.php?x=
/main.php?xlink=
/main1.php?arg=
/main1.php?ln=
/main2.php?ln=
/mainfile.php?MAIN_PATH=
/mambots/content/multithumb/multithumb.php?mosConfig_absolute_path=
/manager/admin/index.php?MGR=
/manager/admin/p_ins.php?MGR=
/manager/admin/u_ins.php?MGR=
/map.php?loc=
/mcf.php?content=
/media.cgi?a=11&t=
/media.php?page=
/mediagallery/public_html/maint/ftpmedia.php?_MG_CONF[path_html]=
/menu.php?functions_file=
/middle.php?file=
/middle.php?page=
/misc.php?do=
/mod*.php?action=
/mod*.php?addr=
/mod*.php?b=
/mod*.php?channel=
/mod*.php?chapter=
/mod*.php?choix=
/mod*.php?cont=
/mod*.php?content=
/mod*.php?corpo=
/mod*.php?d=
/mod*.php?destino=
/mod*.php?dir=
/mod*.php?ev=
/mod*.php?goFile=
/mod*.php?home=
/mod*.php?incl=
/mod*.php?include=
/mod*.php?index=
/mod*.php?ir=
/mod*.php?j=
/mod*.php?lang=
/mod*.php?link=
/mod*.php?m=
/mod*.php?middle=
/mod*.php?module=
/mod*.php?numero=
/mod*.php?oldal=
/mod*.php?OpenPage=
/mod*.php?p****=
/mod*.php?pag=
/mod*.php?page***=
/mod*.php?pagina=
/mod*.php?path=
/mod*.php?pg=
/mod*.php?phpbb_root_path=
/mod*.php?play=
/mod*.php?pre=
/mod*.php?qry=
/mod*.php?recipe=
/mod*.php?secao=
/mod*.php?secc=
/mod*.php?seccion=
/mod*.php?section=
/mod*.php?sekce=
/mod*.php?start=
/mod*.php?strona=
/mod*.php?thispage=
/mod*.php?tipo=
/mod*.php?to=
/mod*.php?v=
/mod*.php?var=
/mod.php?mod=
/modifyform.html?code=
/modul.php?mod=
/module.php?mod=
/modules.php?op=
/modules/4nAlbum/public/displayCategory.php?basepath=
/modules/addons/plugin.php?doc_root=
/modules/agendax/addevent.inc.php?agendax_path=
/modules/AllMyGuests/signin.php?_AMGconfig[cfg_serverpath]=
/modules/coppermine/include/init.inc.php?CPG_M_DIR=
/modules/coppermine/themes/coppercop/theme.php?THEME_DIR=
/modules/coppermine/themes/default/theme.php?THEME_DIR=
/modules/Discipline/CategoryBreakdownTime.php?FocusPath=
/modules/Discipline/CategoryBreakdownTime.php?staticpath=
/modules/Discipline/StudentFieldBreakdown.php?staticpath=
/modules/Forums/admin/admin_db_utilities.php?phpbb_root_path=
/modules/Forums/admin/admin_styles.php?phpbb_root_path=
/modules/kernel/system/startup.php?CFG_PHPGIGGLE_ROOT=
/modules/links/showlinks.php?********_home=&rootdp=zZz&gs********=
/modules/links/submit_links.php?rootdp=zZz&gs********=
/modules/mod_mainmenu.php?mosConfig_absolute_path=
/modules/My_eGallery/index.php?basepath=
/modules/My_eGallery/public/displayCategory.php?basepath=
/modules/newbb_plus/class/forumpollrenderer.php?bbPath[path]=
/modules/PNphpBB2/includes/functions_admin.php?phpbb_root_path=
/modules/poll/inlinepoll.php?********_home=&rootdp=zZz&gs********=
/modules/poll/showpoll.php?********_home=&rootdp=zZz&gs********=
/modules/postguestbook/styles/internal/header.php?tpl_pgb_moddir=
/modules/search/search.php?********_home=&rootdp=zZz&gs********=
/modules/tasks/viewgantt.php?root_dir=
/modules/TotalCalendar/about.php?inc_dir=
/modules/vwar/admin/admin.php?vwar_root=
/modules/vwar/admin/admin.php?vwar_root=index.php?loc=
/modules/vwar/convert/mvcw_conver.php?step=1&vwar_root=
/modules/xgallery/upgrade_album.php?GALLERY_BASEDIR=
/modules/xoopsgallery/upgrade_album.php?GALLERY_BASEDIR=
/module_db.php?pivot_path=
/more.php?sub=
/mwchat/libs/start_lobby.php?CONFIG[MWCHAT_Libs]=
/myevent.php?myevent_path=
/myPHPCalendar/admin.php?cal_dir=
/My_eGallery/public/displayCategory.php?basepath=
/nav.php?g=
/nav.php?go=
/nav.php?lk=
/nav.php?ln=
/nav.php?loc=
/nav.php?nav=
/nav.php?p=
/nav.php?pag=
/nav.php?page=
/nav.php?pagina=
/nav.php?pg=
/ncaster/admin/addons/archive/archive.php?adminfolder=
/ndex.php?p=
/news.cgi?a=114&t=
/news.cgi?a=latest&t=
/news.cgi?t=
/news.php?CONFIG[script_path]=
/news/newstopic_inc.php?indir=
/newsdesk.cgi?a=latest&t=
/newsdesk.cgi?t=
/newsletter/newsletter.php?waroot=
/newsupdate.cgi?a=latest&t=
/news_detail.php?file=
/nota.php?abre=
/nota.php?adresa=
/nota.php?b=
/nota.php?basepath=
/nota.php?base_dir=
/nota.php?category=
/nota.php?channel=
/nota.php?chapter=
/nota.php?cmd=
/nota.php?content=
/nota.php?corpo=
/nota.php?destino=
/nota.php?disp=
/nota.php?doshow=
/nota.php?eval=
/nota.php?filepath=
/nota.php?get=
/nota.php?goFile=
/nota.php?h=
/nota.php?header=
/nota.php?home=
/nota.php?in=
/nota.php?inc=
/nota.php?include=
/nota.php?ir=
/nota.php?itemnav=
/nota.php?ki=
/nota.php?lang=
/nota.php?left=
/nota.php?link=
/nota.php?m=
/nota.php?mid=
/nota.php?mod=
/nota.php?modo=
/nota.php?module=
/nota.php?n=
/nota.php?nivel=
/nota.php?oldal=
/nota.php?opcion=
/nota.php?OpenPage=
/nota.php?option=
/nota.php?pag=
/nota.php?pagina=
/nota.php?panel=
/nota.php?pg=
/nota.php?play=
/nota.php?poll****=
/nota.php?pr=
/nota.php?pre=
/nota.php?qry=
/nota.php?rub=
/nota.php?sec=
/nota.php?secc=
/nota.php?seccion=
/nota.php?second=
/nota.php?seite=
/nota.php?sekce=
/nota.php?showpage=
/nota.php?subject=
/nota.php?t=
/nota.php?tipo=
/nota.php?url=
/nota.php?v=
/noticias.php?arq=
/nuboard_v0.5/admin/index.php?site=
/NuclearBB/tasks/send_queued_emails.php?root_path=
/nuseo/admin/nuseo_admin_d.php?nuseo_dir=
/ocp-103/index.php?req_path=
/old_reports.php?file=
/openi-admin/base/fileloader.php?config[openi_dir]=
/order.php?l=
/order.php?lang=
/order.php?list=
/order.php?ln=
/order.php?p=
/order.php?pag=
/order.php?page=
/order.php?pg=
/order.php?wp=
/order/login.php?svr_rootscript=
/p.php?p=
/padrao.php?****=
/padrao.php?****o=
/padrao.php?*root*=
/padrao.php?*[*]*=
/padrao.php?a=
/padrao.php?abre=
/padrao.php?addr=
/padrao.php?basepath=
/padrao.php?base_dir=
/padrao.php?c=
/padrao.php?choix=
/padrao.php?cont=
/padrao.php?corpo=
/padrao.php?d=
/padrao.php?destino=
/padrao.php?eval=
/padrao.php?filepath=
/padrao.php?h=
/padrao.php?header=
/padrao.php?incl=
/padrao.php?index=
/padrao.php?ir=
/padrao.php?link=
/padrao.php?loc=
/padrao.php?menu=
/padrao.php?menue=
/padrao.php?mid=
/padrao.php?middle=
/padrao.php?n=
/padrao.php?nivel=
/padrao.php?oldal=
/padrao.php?op=
/padrao.php?open=
/padrao.php?OpenPage=
/padrao.php?p****=
/padrao.php?pag=
/padrao.php?page=
/padrao.php?path=
/padrao.php?pre=
/padrao.php?qry=
/padrao.php?read=
/padrao.php?redirect=
/padrao.php?rub=
/padrao.php?secao=
/padrao.php?secc=
/padrao.php?seccion=
/padrao.php?section=
/padrao.php?seite=
/padrao.php?sekce=
/padrao.php?sivu=
/padrao.php?str=
/padrao.php?strona=
/padrao.php?subject=
/padrao.php?tipo=
/padrao.php?type=
/padrao.php?u=
/padrao.php?url=
/padrao.php?var=
/padrao.php?xlink=
/page.php5?id=
/page.php?*[*]*=
/page.php?abre=
/page.php?action=
/page.php?addr=
/page.php?adresa=
/page.php?arq=
/page.php?base_dir=
/page.php?chapter=
/page.php?choix=
/page.php?cmd=
/page.php?cont=
/page.php?doc=
/page.php?e=
/page.php?ev=
/page.php?eval=
/page.php?g=
/page.php?go=
/page.php?goto=
/page.php?inc=
/page.php?incl=
/page.php?ir=
/page.php?left=
/page.php?link=
/page.php?ln=
/page.php?load=
/page.php?loader=
/page.php?mid=
/page.php?middle=
/page.php?mod=
/page.php?modo=
/page.php?module=
/page.php?numero=
/page.php?oldal=
/page.php?OpenPage=
/page.php?option=
/page.php?p****=
/page.php?p=
/page.php?pa=
/page.php?panel=
/page.php?phpbb_root_path=
/page.php?pref=
/page.php?q=
/page.php?qry=
/page.php?read=
/page.php?recipe=
/page.php?redirect=
/page.php?s=
/page.php?secao=
/page.php?section=
/page.php?seite=
/page.php?showpage=
/page.php?sivu=
/page.php?strona=
/page.php?subject=
/page.php?tipo=
/page.php?url=
/page.php?where=
/page.php?z=
/pages.php?page=
/pagina.php?basepath=
/pagina.php?base_dir=
/pagina.php?category=
/pagina.php?channel=
/pagina.php?chapter=
/pagina.php?choix=
/pagina.php?cmd=
/pagina.php?dir=
/pagina.php?ev=
/pagina.php?filepath=
/pagina.php?g=
/pagina.php?go=
/pagina.php?goto=
/pagina.php?header=
/pagina.php?home=
/pagina.php?id=
/pagina.php?in=
/pagina.php?incl=
/pagina.php?include=
/pagina.php?index=
/pagina.php?ir=
/pagina.php?k=
/pagina.php?lang=
/pagina.php?left=
/pagina.php?link=
/pagina.php?load=
/pagina.php?loader=
/pagina.php?loc=
/pagina.php?mid=
/pagina.php?middlePart=
/pagina.php?modo=
/pagina.php?my=
/pagina.php?n=
/pagina.php?nivel=
/pagina.php?numero=
/pagina.php?oldal=
/pagina.php?OpenPage=
/pagina.php?pagina=
/pagina.php?panel=
/pagina.php?path=
/pagina.php?pr=
/pagina.php?pre=
/pagina.php?q=
/pagina.php?read=
/pagina.php?recipe=
/pagina.php?ref=
/pagina.php?sec=
/pagina.php?secao=
/pagina.php?seccion=
/pagina.php?section=
/pagina.php?sekce=
/pagina.php?start=
/pagina.php?str=
/pagina.php?thispage=
/pagina.php?tipo=
/pagina.php?to=
/pagina.php?type=
/pagina.php?u=
/pagina.php?v=
/pagina.php?z=
/palportal/index.php?page=
/path.php?****=
/path.php?*[*]*=
/path.php?action=
/path.php?addr=
/path.php?adresa=
/path.php?category=
/path.php?channel=
/path.php?chapter=
/path.php?cmd=
/path.php?destino=
/path.php?disp=
/path.php?doshow=
/path.php?ev=
/path.php?eval=
/path.php?filepath=
/path.php?goto=
/path.php?header=
/path.php?home=
/path.php?id=
/path.php?in=
/path.php?incl=
/path.php?ir=
/path.php?left=
/path.php?link=
/path.php?load=
/path.php?loader=
/path.php?menue=
/path.php?mid=
/path.php?middle=
/path.php?middlePart=
/path.php?my=
/path.php?nivel=
/path.php?numero=
/path.php?opcion=
/path.php?option=
/path.php?p****=
/path.php?p=
/path.php?page***=
/path.php?panel=
/path.php?path=
/path.php?play=
/path.php?pre=
/path.php?pref=
/path.php?qry=
/path.php?recipe=
/path.php?sec=
/path.php?secao=
/path.php?sivu=
/path.php?sp=
/path.php?start=
/path.php?strona=
/path.php?subject=
/path.php?thispage=
/path.php?tipo=
/path.php?type=
/path.php?var=
/path.php?where=
/path.php?xlink=
/path.php?y=
/path/index.php?function=custom&custom=
/path_of_cpcommerce/_functions.php?prefix
/path_of_cpcommerce/_functions.php?prefix=
/phfito/phfito-post?SRC_PATH=
/photoalb/lib/static/header.php?set_menu=
/PHPDJ_v05/dj/djpage.php?page=
/phpffl/phpffl_***files/program_files/livedraft/admin.php?PHPFFL_FILE_ROOT=
/phpffl/phpffl_***files/program_files/livedraft/livedraft.php?PHPFFL_FILE_ROOT=
/phphtml.php?htmlclass_path=
/PhpLinkExchange/bits_listings.php?svr_rootPhpStart=
/phpopenchat/contrib/yabbse/poc.php?sourcedir=
/phprojekt/lib/config.inc.php?path_pre=
/phprojekt/lib/gpcs_vars.inc.php?path_pre=
/phprojekt/lib/layout/venus/venus.php?path_pre=
/phprojekt/lib/lib.inc.php?path_pre=
/phpsecurityadmin/include/logout.php?PSA_PATH=
/phpshop/index.php?base_dir=
/phpwcms/include/inc_ext/spaw/dialogs/table.php?spaw_root=
/phpwcms_template/inc_script/frontend_render/navigation/config_HTML_MENU.php?HTML_MENU_DirPath=
/phpwcms_template/inc_script/frontend_render/navigation/config_PHPLM.php?HTML_MENU_DirPath=
/pivot/modules/module_db.php?pivot_path=
/pm/lib.inc.php?pm_path=
/poll/comments.php?id={${include($ddd)}}{${exit()}}&ddd=
/pop.php?base=
/popup_window.php?site_isp_root=
/port.php?content=
/powerup.cgi?a=latest&t=
/ppa/inc/functions.inc.php?config[ppa_root_path]=
/prepare.php?xcart_dir=
/press.php?*root*=
/press.php?*[*]*=
/press.php?abre=
/press.php?addr=
/press.php?base_dir=
/press.php?category=
/press.php?channel=
/press.php?destino=
/press.php?dir=
/press.php?ev=
/press.php?get=
/press.php?goFile=
/press.php?home=
/press.php?i=
/press.php?id=
/press.php?inc=
/press.php?incl=
/press.php?include=
/press.php?ir=
/press.php?itemnav=
/press.php?lang=
/press.php?link=
/press.php?loader=
/press.php?menu=
/press.php?mid=
/press.php?middle=
/press.php?modo=
/press.php?module=
/press.php?my=
/press.php?nivel=
/press.php?opcion=
/press.php?OpenPage=
/press.php?option=
/press.php?p****=
/press.php?pa=
/press.php?page***=
/press.php?page=
/press.php?pagina=
/press.php?panel=
/press.php?param=
/press.php?path=
/press.php?pg=
/press.php?pr=
/press.php?pref=
/press.php?redirect=
/press.php?rub=
/press.php?second=
/press.php?seite=
/press.php?strona=
/press.php?subject=
/press.php?t=
/press.php?thispage=
/press.php?to=
/press.php?type=
/press.php?where=
/press.php?xlink=
/presse.php?do=
/principal.php?abre=
/principal.php?addr=
/principal.php?b=
/principal.php?basepath=
/principal.php?choix=
/principal.php?cont=
/principal.php?conteudo=
/principal.php?corpo=
/principal.php?d=
/principal.php?destino=
/principal.php?disp=
/principal.php?ev=
/principal.php?eval=
/principal.php?f=
/principal.php?filepath=
/principal.php?goto=
/principal.php?header=
/principal.php?home=
/principal.php?id=
/principal.php?in=
/principal.php?inc=
/principal.php?index=
/principal.php?ir=
/principal.php?ki=
/principal.php?l=
/principal.php?left=
/principal.php?link=
/principal.php?load=
/principal.php?loader=
/principal.php?loc=
/principal.php?menue=
/principal.php?middle=
/principal.php?middlePart=
/principal.php?module=
/principal.php?my=
/principal.php?n=
/principal.php?nivel=
/principal.php?oldal=
/principal.php?opcion=
/principal.php?p=
/principal.php?pag=
/principal.php?pagina=
/principal.php?param=
/principal.php?phpbb_root_path=
/principal.php?poll****=
/principal.php?pr=
/principal.php?pre=
/principal.php?pref=
/principal.php?q=
/principal.php?read=
/principal.php?recipe=
/principal.php?ref=
/principal.php?rub=
/principal.php?s=
/principal.php?secc=
/principal.php?seccion=
/principal.php?seite=
/principal.php?strona=
/principal.php?subject=
/principal.php?tipo=
/principal.php?to=
/principal.php?type=
/principal.php?url=
/principal.php?viewpage=
/principal.php?w=
/principal.php?z=
/print.php?****=
/print.php?*root*=
/print.php?addr=
/print.php?basepath=
/print.php?base_dir=
/print.php?category=
/print.php?chapter=
/print.php?choix=
/print.php?cont=
/print.php?dir=
/print.php?disp=
/print.php?doshow=
/print.php?g=
/print.php?goFile=
/print.php?goto=
/print.php?header=
/print.php?in=
/print.php?inc=
/print.php?itemnav=
/print.php?ki=
/print.php?l=
/print.php?left=
/print.php?link=
/print.php?loc=
/print.php?menu=
/print.php?menue=
/print.php?middle=
/print.php?middlePart=
/print.php?module=
/print.php?my=
/print.php?numero=
/print.php?opcion=
/print.php?open=
/print.php?OpenPage=
/print.php?option=
/print.php?p****=
/print.php?pag=
/print.php?page=
/print.php?pager=
/print.php?param=
/print.php?path=
/print.php?play=
/print.php?poll****=
/print.php?pre=
/print.php?r=
/print.php?read=
/print.php?rub=
/print.php?s=
/print.php?sekce=
/print.php?sivu=
/print.php?sp=
/print.php?str=
/print.php?strona=
/print.php?table=
/print.php?thispage=
/print.php?tipo=
/print.php?type=
/print.php?u=
/print.php?where=
/prod.php?prod=
/proddetail.php?prod=
/products.php?prod=
/produit.php?prod=
/produkt.php?prod=
/protection.php?action=logout&siteurl=
/provider/auth.php?xcart_dir=
/public_includes/pub_blocks/activecontent.php?vsDragonRootPath=
/read.php?fpage=
/reporter.cgi?t=
/reports.php?sub=
/rss.php?phpraid_dir=
/s.php?table=
/s1.php?ln=
/scan
/search.php?cutepath=
/search.php?exec=
/sendpage.php?page=
/send_reminders.php?includedir=
/senetman/html/index.php?page=
/services.php?page=
/shop.php?prod=
/shop.pl/page=
/shoutbox/expanded.php?conf=
/show.php?*root*=
/show.php?abre=
/show.php?adresa=
/show.php?b=
/show.php?base_dir=
/show.php?channel=
/show.php?chapter=
/show.php?cmd=
/show.php?corpo=
/show.php?d=
/show.php?disp=
/show.php?file=
/show.php?filepath=
/show.php?get=
/show.php?go=
/show.php?header=
/show.php?home=
/show.php?inc=
/show.php?incl=
/show.php?include=
/show.php?index=
/show.php?ir=
/show.php?j=
/show.php?ki=
/show.php?l=
/show.php?left=
/show.php?loader=
/show.php?m=
/show.php?mid=
/show.php?middlePart=
/show.php?modo=
/show.php?module=
/show.php?my=
/show.php?n=
/show.php?nivel=
/show.php?oldal=
/show.php?p****=
/show.php?page***=
/show.php?page1=
/show.php?page=
/show.php?pagina=
/show.php?param=
/show.php?path=
/show.php?play=
/show.php?pre=
/show.php?product=
/show.php?qry=
/show.php?r=
/show.php?read=
/show.php?recipe=
/show.php?redirect=
/show.php?seccion=
/show.php?second=
/show.php?sp=
/show.php?thispage=
/show.php?to=
/show.php?type=
/show.php?x=
/show.php?xlink=
/show.php?z=
/show_news.php?cutepath=
/side.php?arq=
/side.php?table=
/side.php?vis=
/site.php?arq=
/site.php?meio=
/site.php?table=
/sitio.php?****=
/sitio.php?****o=
/sitio.php?*root*=
/sitio.php?abre=
/sitio.php?addr=
/sitio.php?category=
/sitio.php?chapter=
/sitio.php?content=
/sitio.php?destino=
/sitio.php?disp=
/sitio.php?doshow=
/sitio.php?e=
/sitio.php?ev=
/sitio.php?get=
/sitio.php?go=
/sitio.php?goFile=
/sitio.php?inc=
/sitio.php?incl=
/sitio.php?index=
/sitio.php?ir=
/sitio.php?left=
/sitio.php?menu=
/sitio.php?menue=
/sitio.php?mid=
/sitio.php?middlePart=
/sitio.php?modo=
/sitio.php?nivel=
/sitio.php?oldal=
/sitio.php?opcion=
/sitio.php?option=
/sitio.php?page***=
/sitio.php?param=
/sitio.php?pg=
/sitio.php?pr=
/sitio.php?qry=
/sitio.php?r=
/sitio.php?read=
/sitio.php?recipe=
/sitio.php?redirect=
/sitio.php?rub=
/sitio.php?sec=
/sitio.php?secao=
/sitio.php?secc=
/sitio.php?section=
/sitio.php?sivu=
/sitio.php?sp=
/sitio.php?start=
/sitio.php?strona=
/sitio.php?t=
/sitio.php?tipo=
/skin/zero_vote/ask_password.php?dir=
/skin/zero_vote/error.php?dir=
/skins/advanced/advanced1.php?pluginpath[0]=
/smarty.php?xcart_dir=
/smarty_config.php?root_dir=
/solpot.html?****=
/source/mod/rss/channeledit.php?Codebase=
/source/mod/rss/post.php?Codebase=
/source/mod/rss/view.php?Codebase=
/source/mod/rss/viewitem.php?Codebase=
/sources/functions.php?CONFIG[main_path]=
/sources/join.php?FORM[url]=owned&CONFIG[captcha]=1&CONFIG[path]=
/sources/template.php?CONFIG[main_path]=
/spid/lang/lang.php?lang_path=
/SQuery/lib/gore.php?libpath=
/squirrelcart/cart_content.php?cart_isp_root=
/squito/photolist.inc.php?photoroot=
/standard.php?****=
/standard.php?*[*]*=
/standard.php?abre=
/standard.php?action=
/standard.php?base_dir=
/standard.php?channel=
/standard.php?chapter=
/standard.php?cmd=
/standard.php?cont=
/standard.php?destino=
/standard.php?dir=
/standard.php?e=
/standard.php?ev=
/standard.php?eval=
/standard.php?go=
/standard.php?goFile=
/standard.php?goto=
/standard.php?home=
/standard.php?in=
/standard.php?include=
/standard.php?index=
/standard.php?j=
/standard.php?lang=
/standard.php?link=
/standard.php?menu=
/standard.php?middle=
/standard.php?my=
/standard.php?numero=
/standard.php?oldal=
/standard.php?op=
/standard.php?open=
/standard.php?pagina=
/standard.php?panel=
/standard.php?param=
/standard.php?phpbb_root_path=
/standard.php?poll****=
/standard.php?pr=
/standard.php?pre=
/standard.php?pref=
/standard.php?q=
/standard.php?qry=
/standard.php?ref=
/standard.php?s=
/standard.php?secc=
/standard.php?seccion=
/standard.php?section=
/standard.php?showpage=
/standard.php?sivu=
/standard.php?str=
/standard.php?subject=
/standard.php?url=
/standard.php?var=
/standard.php?viewpage=
/standard.php?w=
/standard.php?where=
/standard.php?xlink=
/standard.php?z=
/start.php?****=
/start.php?*root*=
/start.php?abre=
/start.php?addr=
/start.php?adresa=
/start.php?b=
/start.php?basepath=
/start.php?base_dir=
/start.php?chapter=
/start.php?cmd=
/start.php?corpo=
/start.php?destino=
/start.php?eval=
/start.php?go=
/start.php?header=
/start.php?home=
/start.php?id=
/start.php?in=
/start.php?include=
/start.php?index=
/start.php?ir=
/start.php?lang=
/start.php?load=
/start.php?loader=
/start.php?mid=
/start.php?mod=
/start.php?modo=
/start.php?module=
/start.php?nivel=
/start.php?o=
/start.php?oldal=
/start.php?op=
/start.php?option=
/start.php?p****=
/start.php?p=
/start.php?pag=
/start.php?page***=
/start.php?page=
/start.php?panel=
/start.php?param=
/start.php?pg=
/start.php?play=
/start.php?poll****=
/start.php?rub=
/start.php?s=
/start.php?secao=
/start.php?seccion=
/start.php?seite=
/start.php?showpage=
/start.php?sivu=
/start.php?sp=
/start.php?str=
/start.php?strona=
/start.php?thispage=
/start.php?tipo=
/start.php?where=
/start.php?xlink=
/stphpapplication.php?STPHPLIB_DIR=
/stphpbtnimage.php?STPHPLIB_DIR=
/stphpform.php?STPHPLIB_DIR=
/str.php?l=
/str.php?lang=
/str.php?ln=
/str.php?p=
/str.php?page=
/sub*.php?****=
/sub*.php?*root*=
/sub*.php?*[*]*=
/sub*.php?abre=
/sub*.php?action=
/sub*.php?adresa=
/sub*.php?b=
/sub*.php?basepath=
/sub*.php?base_dir=
/sub*.php?category=
/sub*.php?channel=
/sub*.php?chapter=
/sub*.php?cont=
/sub*.php?content=
/sub*.php?corpo=
/sub*.php?destino=
/sub*.php?g=
/sub*.php?go=
/sub*.php?goFile=
/sub*.php?header=
/sub*.php?id=
/sub*.php?include=
/sub*.php?ir=
/sub*.php?itemnav=
/sub*.php?j=
/sub*.php?k=
/sub*.php?lang=
/sub*.php?left=
/sub*.php?link=
/sub*.php?load=
/sub*.php?menue=
/sub*.php?mid=
/sub*.php?middle=
/sub*.php?mod=
/sub*.php?modo=
/sub*.php?module=
/sub*.php?my=
/sub*.php?oldal=
/sub*.php?op=
/sub*.php?open=
/sub*.php?OpenPage=
/sub*.php?option=
/sub*.php?p****=
/sub*.php?pa=
/sub*.php?pag=
/sub*.php?panel=
/sub*.php?path=
/sub*.php?phpbb_root_path=
/sub*.php?play=
/sub*.php?pre=
/sub*.php?qry=
/sub*.php?recipe=
/sub*.php?rub=
/sub*.php?s=
/sub*.php?sec=
/sub*.php?secao=
/sub*.php?secc=
/sub*.php?seite=
/sub*.php?sp=
/sub*.php?str=
/sub*.php?thispage=
/sub*.php?u=
/sub*.php?viewpage=
/sub*.php?where=
/sub*.php?z=
/sub.php?menu=
/sub.php?s=
/sub.php?sub=
/support/mailling/maillist/inc/initdb.php?absolute_path=
/support_page.cgi?file_****=
/surveys/survey.inc.php?path=
/tags.php?BBCodeFile=
/task.php?task=
/tellmatic/include/libchart-1.1/libchart.php?tm_includepath=
/template.php?****=
/template.php?****o=
/template.php?*[*]*=
/template.php?a=
/template.php?addr=
/template.php?basepath=
/template.php?base_dir=
/template.php?c=
/template.php?choix=
/template.php?cont=
/template.php?content=
/template.php?corpo=
/template.php?dir=
/template.php?doshow=
/template.php?e=
/template.php?f=
/template.php?goto=
/template.php?h=
/template.php?header=
/template.php?ir=
/template.php?k=
/template.php?lang=
/template.php?left=
/template.php?load=
/template.php?menue=
/template.php?mid=
/template.php?mod=
/template.php?nivel=
/template.php?op=
/template.php?opcion=
/template.php?pag=
/template.php?page=
/template.php?pagina
/template.php?pagina=
/template.php?panel=
/template.php?param=
/template.php?path=
/template.php?play=
/template.php?pre=
/template.php?qry=
/template.php?ref=
/template.php?s=
/template.php?secao=
/template.php?second=
/template.php?section=
/template.php?seite=
/template.php?sekce=
/template.php?showpage=
/template.php?sp=
/template.php?str=
/template.php?t=
/template.php?thispage=
/template.php?tipo=
/template.php?viewpage=
/template.php?where=
/template.php?y=
/templates/headline_temp.php?nst_inc=
/templates/mangobery/footer.sample.php?Site_Path=
/test.php?page=
/tikiwiki/tiki-graph_formula.php?w=1&h=1&s=1&min=1&max=2&f[]=x.tan.phpinfo()&t=png&title=
/tools/send_reminders.php?includedir=
/tools/send_reminders.php?includedir= allinurl:day.php?date=
/tools/send_reminders.php?noSet=0&includedir=
/trans.php?trans=
/trans/trans.php?trans=&p=
/trans/trans.php?trans=&page=
/trans/trans.php?trans=en&page=
/trans/trans.php?trans=eng&page=
/trans/trans.php?trans=fr&page=
/trans/trans.php?trans=ko&page=
/video.php?content=
/view.php?****=
/view.php?*[*]*=
/view.php?adresa=
/view.php?b=
/view.php?channel=
/view.php?chapter=
/view.php?choix=
/view.php?cmd=
/view.php?content=
/view.php?disp=
/view.php?get=
/view.php?go=
/view.php?goFile=
/view.php?goto=
/view.php?header=
/view.php?incl=
/view.php?ir=
/view.php?ki=
/view.php?lang=
/view.php?load=
/view.php?loader=
/view.php?mid=
/view.php?middle=
/view.php?mod=
/view.php?oldal=
/view.php?option=
/view.php?pag=
/view.php?page=
/view.php?panel=
/view.php?pg=
/view.php?phpbb_root_path=
/view.php?poll****=
/view.php?pr=
/view.php?qry=
/view.php?recipe=
/view.php?redirect=
/view.php?sec=
/view.php?secao=
/view.php?seccion=
/view.php?second=
/view.php?seite=
/view.php?showpage=
/view.php?sp=
/view.php?str=
/view.php?sub=
/view.php?table=
/view.php?to=
/view.php?type=
/view.php?u=
/view.php?var=
/view.php?where=
/voir.php?inc=
/ws/get_events.php?includedir=
/ws/get_reminders.php?includedir=
/ws/login.php?includedir=
/yabbse/Sources/Packages.php?sourcedir=
/zipndownload.php?PP_PATH=
/[MyAlbum_DIR]/********.inc.php?langs_dir=
/[Script
02/forum_topic.php?id=
4images Administration Control Panel
737en.php?id=
94FBR "ADOBE PHOTOSHOP"
?act=
?action=
?cat=
?id=
?intitle:index.of? mp3 artist-name-here
?intitle:index.of? mp3 name
?page=
?pagerequested=
?pid=
about.asp?cartID=
about.cfm?cartID=
about.php?cartID=
about.php?id=
aboutbook.php?id=
aboutchiangmai/details.asp?id=
aboutchiangmai/details.php?id=
aboutprinter.shtml
abouttheregions_province.php?id=
abouttheregions_village.php?id=
about_us.asp?id=
about_us.php?id=
abroad/page.asp?cid=
abroad/page.php?cid=
accinfo.asp?cartId=
accinfo.cfm?cartId=
accinfo.php?cartId=
acclogin.asp?cartID=
acclogin.cfm?cartID=
acclogin.php?cartID=
ad.php?id=
add-to-cart.asp?ID=
add-to-cart.cfm?ID=
add-to-cart.php?ID=
add.asp?bookid=
add.cfm?bookid=
add.php?bookid=
addcart.asp?
addcart.cfm?
addcart.php?
addcolumn.php?id=
addimage.php?cid=
addItem.asp
addItem.cfm
addItem.php
addpages.php?id=
addsiteform.php?catid=
addToCart.asp?idProduct=
addToCart.cfm?idProduct=
addToCart.php?idProduct=
addtomylist.asp?ProdId=
addtomylist.cfm?ProdId=
addtomylist.php?ProdId=
add_cart.asp?num=
add_cart.cfm?num=
add_cart.php?num=
adetail.php?id=
admin.php?page=
admin/doeditconfig.php?thispath=../includes&config[path]=
admin/index.php?o=
adminEditProductFields.asp?intProdID=
adminEditProductFields.cfm?intProdID=
adminEditProductFields.php?intProdID=
administrator/components/com_a6mambocredits/admin.a6mambocredits.php?mosConfig_live_site=
administrator/components/com_comprofiler/plugin.class.php?mosConfig_absolute_path=
administrator/components/com_comprofiler/plugin.class.php?mosConfig_absolute_path= /tools/send_reminders.php?includedir= allinurl:day.php?date=
administrator/components/com_cropimage/admin.cropcanvas.php?cropimagedir=
administrator/components/com_cropimage/admin.cropcanvas.php?cropimagedir=modules/My_eGallery/index.php?basepath=
administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php?mosConfig_absolute_path=
administrator/components/com_mgm/help.mgm.php?mosConfig_absolute_path=
administrator/components/com_peoplebook/param.peoplebook.php?mosConfig_absolute_path=
administrator/components/com_remository/admin.remository.php?mosConfig_absolute_path=
administrator/components/com_remository/admin.remository.php?mosConfig_absolute_path= /tags.php?BBCodeFile=
administrator/components/com_webring/admin.webring.docs.php?component_dir=
ads/index.php?cat=
advSearch_h.asp?idCategory=
advSearch_h.cfm?idCategory=
advSearch_h.php?idCategory=
affiliate-agreement.cfm?storeid=
affiliate.asp?ID=
affiliate.cfm?ID=
affiliate.php?ID=
affiliates.asp?id=
affiliates.cfm?id=
affiliates.php?id=
aggregator.php?id=
AIM buddy lists
airactivity.cfm?id=
akocomments.php?mosConfig_absolute_path=
aktuelles/meldungen-detail.asp?id=
aktuelles/meldungen-detail.php?id=
aktuelles/veranstaltungen/detail.asp?id=
aktuelles/veranstaltungen/detail.php?id=
allintext:"Copperfasten Technologies" "Login"
allintext:"Index Of" "cookies.txt"
allintext:@gmail.com filetype:log
allintext:\"Index Of\" \"sftp-config.json\"
allintitle: "index of/admin"
allintitle: "index of/root"
allintitle: restricted filetype :mail
allintitle: restricted filetype:doc site:gov
allintitle: sensitive filetype:doc
allintitle:"Network Camera NetworkCamera"
allintitle:"Welcome to the Cyclades"
allintitle:*.php?filename=*
allintitle:*.php?logon=*
allintitle:*.php?page=*
allintitle:.."Test page for Apache Installation.."
allintitle:admin.php
allintitle:\"Pi-hole Admin Console\"
allinurl: admin mdb
allinurl:".r{}_vti_cnf/"
allinurl:"exchange/logon.asp"
allinurl:"index.php" "site=sglinks"
allinurl:*.php?txtCodiInfo=
allinurl:.br/index.php?loc=
allinurl:/examples/jsp/snp/snoop.jsp
allinurl:admin mdb
allinurl:auth_user_file.txt
allinurl:cdkey.txt
allinurl:control/multiview
allinurl:install/install.php
allinurl:intranet admin
allinurl:servlet/SnoopServlet
allinurl:wps/portal/ login
al_initialize.php?alpath=
An unexpected token "END-OF-STATEMENT" was found
Analysis Console for Incident Databases
ancillary.asp?ID=
ancillary.cfm?ID=
ancillary.php?ID=
animal/products.php?id=
anj.php?id=
announce.php?id=
answer/default.asp?pollID=
answer/default.php?pollID=
AnyBoard" intitle:"If you are a new user:" intext:"Forum
AnyBoard" inurl:gochat -edu
architect_full.php?id=
archive.asp?id=
archive.cfm?id=
archive.php?id=
archive/get.asp?message_id=
archive/get.php?message_id=
ARDetail.asp?ID=
art.asp?id=
art.php?id=
artform.cfm?id=
article.asp?id=
article.cfm?id=
article.php?id=
article.php?ID=
article/article.php?id=
article/index.php?id=
articlecategory.asp?id=
articlecategory.php?id=
articles.asp?id=
articles.php?id=
articles/article.php?id=
articles/details.php?id=
articles/index.php?id=
article_full.php?id=
article_preview.asp?id=
article_preview.php?id=
artikelinfo.php?id=
artist.php?id=
artistdetail.php?ID=
ArtistDetail.php?id=
artists.php?id=
artists/details.php?id=
artists/index.php?id=
artists/story/index.php?id=
artist_art.asp?id=
artist_art.php?id=
artist_info.php?artistId=
art_page.php?id=
asp
ASP.login_aspx "ASP.NET_SessionId"
asp/event.asp?id=
asp/fid8E1BED06B1301BAE3ED64383D5F619E3B1997A70.aspx?s=
asp/fid985C124FBD9EF3A29BA8F40521F12D097B0E2016.aspx?s=
asp/index.asp?id=
aspx?PageID
auction/item.asp?id=
auction/item.php?id=
auction_details.php?auction_id=
authorDetails.asp?bookID=
authorDetails.php?bookID=
auth_user_file.txt
avatar.php?page=
avd_start.php?avd=
awards/index.php?input1=
AXIS Camera exploit
band_info.php?id=
base.php?*[*]*=
base.php?abre=
base.php?adresa=
base.php?basepath=
base.php?base_dir=
base.php?body=
base.php?category=
base.php?chapter=
base.php?choix=
base.php?cont=
base.php?disp=
base.php?doshow=
base.php?ev=
base.php?eval=
base.php?filepath=
base.php?home=
base.php?id=
base.php?incl=
base.php?include=
base.php?ir=
base.php?itemnav=
base.php?k=
base.php?ki=
base.php?l=
base.php?lang=
base.php?link=
base.php?loc=
base.php?mid=
base.php?middle=
base.php?middlePart=
base.php?module=
base.php?name=
base.php?numero=
base.php?oldal=
base.php?opcion=
base.php?pa=
base.php?pag=
base.php?pageweb=
base.php?panel=
base.php?path=
base.php?phpbb_root_path=
base.php?play=
base.php?pname=
base.php?rub=
base.php?seccion=
base.php?second=
base.php?seite=
base.php?sekce=
base.php?sivu=
base.php?str=
base.php?subject=
base.php?t=
base.php?texto=
base.php?to=
base.php?v=
base.php?var=
base.php?w=
basket.asp?id=
basket.cfm?id=
basket.php?id=
bayer/dtnews.asp?id=
bayer/dtnews.php?id=
bbs/bbsView.asp?id=
bbs/bbsView.php?id=
bbs/view.asp?no=
bbs/view.php?no=
bbs/view.php?tbl=
bb_usage_stats/include/bb_usage_stats.php?phpbb_root_path=
bearstore/store.php?cat_id=
beitrag_D.asp?id=
beitrag_D.php?id=
beitrag_F.asp?id=
beitrag_F.php?id=
bid/topic.asp?TopicID=
bid/topic.php?TopicID=
big.php?pathtotemplate=
Bill Gates intitle:”index.of” “parent directory” “size” “last modified” “description” Microsoft (pdf|txt|epub|doc|docx) -inurl:(jsp|php|html|aspx|htm|cf|shtml|ebooks|ebook) -site:.info
blank.php?abre=
blank.php?action=
blank.php?basepath=
blank.php?base_dir=
blank.php?body=
blank.php?category=
blank.php?channel=
blank.php?corpo=
blank.php?destino=
blank.php?dir=
blank.php?filepath=
blank.php?get=
blank.php?goFile=
blank.php?goto=
blank.php?h=
blank.php?header=
blank.php?id=
blank.php?in=
blank.php?incl=
blank.php?ir=
blank.php?itemnav=
blank.php?j=
blank.php?ki=
blank.php?lang=
blank.php?left=
blank.php?link=
blank.php?loader=
blank.php?menu=
blank.php?mod=
blank.php?name=
blank.php?o=
blank.php?oldal=
blank.php?open=
blank.php?OpenPage=
blank.php?pa=
blank.php?page=
blank.php?pagina=
blank.php?panel=
blank.php?path=
blank.php?phpbb_root_path=
blank.php?pname=
blank.php?pollname=
blank.php?pr=
blank.php?pre=
blank.php?pref=
blank.php?qry=
blank.php?read=
blank.php?ref=
blank.php?rub=
blank.php?section=
blank.php?sivu=
blank.php?sp=
blank.php?strona=
blank.php?subject=
blank.php?t=
blank.php?url=
blank.php?var=
blank.php?where=
blank.php?xlink=
blank.php?z=
blog.asp?blog=
blog.php?blog=
blog/?p=
blog/index.asp?idBlog=
blog/index.php?idBlog=
Blog/viewpost.php?id=
blog_detail.asp?id=
blog_detail.php?id=
blpage.php?id=
board/board.html?table=
board/kboard.php?board=
board/read.asp?tid=
board/read.php?tid=
board/showthread.asp?t=
board/showthread.php?t=
board/templete/sycho/input.php?table=
board/view.asp?no=
board/view.php?no=
board/viewtopic.php?id=
board/view_temp.php?table=
boardView.asp?bbs=
boardView.php?bbs=
board_view.asp?s_board_id=
board_view.html?id=
board_view.php?s_board_id=
boat_plans.asp?id=
book-details.php?id=
Book.asp?bookID=
book.asp?ID=
book.asp?id=
book.asp?ISBN=
book.asp?isbn=
Book.cfm?bookID=
book.html?isbn=
Book.php?bookID=
book.php?bookid=
book.php?ID=
book.php?id=
book.php?ISBN=
book.php?isbn=
book/bookcover.asp?bookid=
book/bookcover.php?bookid=
book2.php?id=
BookDetails.asp?ID=
bookDetails.asp?id=
BookDetails.cfm?ID=
BookDetails.php?ID=
bookDetails.php?id=
booking.php?id=
booking.php?s=
booking/bandinfo.php?id=
bookmark/mybook/bookmark.asp?bookPageNo=
bookmark/mybook/bookmark.php?bookPageNo=
bookpage.asp?id=
bookpage.php?id=
books.asp?id=
books.php?id=
books/book.asp?proj_nr=
books/book.php?proj_nr=
bookSingle.php?bookId=
bookview.asp?id=
bookview.php?id=
book_detail.asp?BookID=
book_detail.php?BookID=
book_dete.php?bookID=
book_list.asp?bookid=
book_list.cfm?bookid=
book_list.php?bookid=
book_view.asp?bookid=
book_view.cfm?bookid=
book_view.php?bookid=
bout.php?cartID=
bpac/calendar/event.asp?id=
bpac/calendar/event.php?id=
bp_ncom.php?bnrep=
brand.asp?id=
brand.php?id=
brief.php?id=
browse.asp?catid=
browse.cfm?catid=
browse.php?catid=
browse.php?cid=
browse/book.asp?journalID=
browse/book.php?journalID=
browsepr.asp?pr=
browsepr.php?pr=
browse_item_details.asp
Browse_Item_Details.asp?Store_Id=
browse_item_details.cfm
Browse_Item_Details.cfm?Store_Id=
browse_item_details.php
Browse_Item_Details.php?Store_Id=
bug.php?id=
business/details.php?id=
buy.asp?
buy.asp?bookid=
buy.cfm?
buy.cfm?bookid=
buy.php?
buy.php?bookid=
buy.php?category=
bycategory.asp?id=
bycategory.cfm?id=
bycategory.php?id=
calendar.php?event_id=
calendar/event.asp?id=
calendar/event.php?id=
calendar/item.php?id=
calendar/week.php?cid=
camera linksys inurl:main.cgi
campaigns.php?id=
campkc-today.php?Start=
campkc-view-event.php?Item_ID=
camp_details.php?id=
canal/imap.php?id=
Canon Webview netcams
car.php?id=
cardetail.php?id=
cardetails.php?id=
cardinfo.asp?card=
cardinfo.cfm?card=
cardinfo.php?card=
cardIssuance/product.php?pid=
carinfo.php?id=
carry-detail.php?prodID=
carsdetail.php?id=
cart.asp?action=
cart.asp?cart_id=
cart.asp?id=
cart.cfm?action=
cart.cfm?cart_id=
cart.cfm?id=
cart.php?action=
cart.php?cart_id=
cart.php?id=
cart/addToCart.asp?cid=
cart/addToCart.php?cid=
cart/detail_prod.php?id=
cart/home.php?cat=
cart/item_show.php?itemID=
cart/product.asp?productid=
cart/product.php?productid=
cart/prod_details.php?prodid=
cart/prod_subcat.php?id=
cartadd.asp?id=
cartadd.cfm?id=
cartadd.php?id=
cart_additem.asp?id=
cart_additem.cfm?id=
cart_additem.php?id=
cart_validate.asp?id=
cart_validate.cfm?id=
cart_validate.php?id=
car_details.php?id=
cat.asp?cat_id=
cat.asp?iCat=
cat.asp?id=
cat.cfm?iCat=
cat.php?cat=
cat.php?cat_id=
cat.php?iCat=
cat/?catid=
catalog.asp
catalog.asp?CatalogID=
catalog.cfm
catalog.cfm?CatalogID=
catalog.php
catalog.php?CAT=
catalog.php?CatalogID=
catalog/index.php?cPath=
catalog/main.asp?cat_id=
catalog/main.php?cat_id=
catalog/product.asp?cat_id=
catalog/product.asp?pid=
catalog/product.php?cat_id=
catalog/product.php?pid=
catalog/product_info.php?products_id=
catalog_item.asp?ID=
catalog_item.cfm?ID=
catalog_item.php?ID=
catalog_main.asp?catid=
catalog_main.cfm?catid=
catalog_main.php?catid=
Catalog_View_Summary.php?ID=
categories.asp?cat=
categories.php?cat=
categories.php?catid=
categories.php?id=
categories.php?parent_id=
categories.php?start=
category.asp
category.asp?c=
category.asp?catid=
category.asp?CID=
category.asp?cid=
Category.asp?cid=
category.asp?id=
category.asp?id_category=
category.cfm
category.cfm?catid=
category.php
category.php?c=
category.php?categoryid=
category.php?category_id=
category.php?Category_ID=
category.php?catid=
category.php?catId=
category.php?catID=
category.php?cat_id=
category.php?CID=
category.php?cid=
Category.php?cid=
category.php?id=
category.php?ID=
category.php?id_category=
category/index_pages.php?category_id=
categorydisplay.asp?catid=
categorydisplay.cfm?catid=
categorydisplay.php?catid=
category_id.php?id=
category_list.asp?id=
category_list.cfm?id=
category_list.php?id=
category_view.php?category_id=
cats.asp?cat=
cats.php?cat=
cats_disp.php?cat=
cbmer/congres/page.asp?LAN=
cbmer/congres/page.php?LAN=
cc/showthread.php?p=
cc/showthread.php?t=
cd.php?id=
cei/cedb/projdetail.asp?projID=
cei/cedb/projdetail.php?projID=
cemetery.asp?id=
cemetery.php?id=
cfm
cfmx?PageID
CGI:IRC Login
cgiirc.conf
chalets.php?id=
chamber/members.php?id=
channel/channel-layout.asp?objId=
channel/channel-layout.php?objId=
channel_id=
chappies.php?id=
cheats/details.php?ID=
cheats/item.php?itemid=
checknews.php?id=
checkout.asp?cartid=
checkout.asp?UserID=
checkout.cfm?cartid=
checkout.cfm?UserID=
checkout.php?cartid=
checkout.php?UserID=
checkout1.asp?cartid=
checkout1.cfm?cartid=
checkout1.php?cartid=
checkout_confirmed.asp?order_id=
checkout_confirmed.cfm?order_id=
checkout_confirmed.php?order_id=
clanek.php4?id=
clan_page.asp?cid=
clan_page.php?cid=
classes/adodbt/sql.php?classes_dir=
classified/detail.php?siteid=
classifieds/detail.asp?siteid=
classifieds/detail.php?siteid=
classifieds/showproduct.asp?product=
classifieds/showproduct.php?product=
clear/store/products.php?product_category=
cloudbank/detail.asp?ID=
cloudbank/detail.php?ID=
club.asp?cid=
club.php?cid=
clubpage.php?id=
cm/public/news/news.php?newsid=
cms/publications.php?id=
cms/showpage.php?cid=
cms/story.php?id=
Coldfusion Error Pages
collectionitem.php?id=
colourpointeducational/more_details.asp?id=
colourpointeducational/more_details.php?id=
comedy_to_go.php?id=
Comersus.mdb database
comersus_listCategoriesAndProducts.asp?idCategory=
comersus_listCategoriesAndProducts.cfm?idCategory=
comersus_listCategoriesAndProducts.php?idCategory=
comersus_optEmailToFriendForm.asp?idProduct=
comersus_optEmailToFriendForm.cfm?idProduct=
comersus_optEmailToFriendForm.php?idProduct=
comersus_optReviewReadExec.asp?idProduct=
comersus_optReviewReadExec.cfm?idProduct=
comersus_optReviewReadExec.php?idProduct=
comersus_viewItem.asp?idProduct=
comersus_viewItem.cfm?idProduct=
comersus_viewItem.php?idProduct=
comments.asp?id=
comments.php?id=
comments_form.asp?ID=
comments_form.cfm?ID=
comments_form.php?ID=
communique_detail.php?id=
community/calendar-event-fr.asp?id=
community/calendar-event-fr.php?id=
Company%20Info.php?id=
company.asp?ID=
company/news.php?id=
company_details.php?ID=
components/com_artlinks/artlinks.dispnew.php?mosConfig_absolute_path=
components/com_cpg/cpg.php?mosConfig_absolute_path=
components/com_extcalendar/admin_events.php?CONFIG_EXT[LANGUAGES_DIR]=
components/com_extended_registration/registration_detailed.inc.php?mosConfig_absolute_path=
components/com_forum/download.php?phpbb_root_path=
components/com_galleria/galleria.html.php?mosConfig_absolute_path=
components/com_mtree/Savant2/Savant2_Plugin_stylesheet.php?mosConfig_absolute_path=
components/com_performs/performs.php?mosConfig_absolute_path=
components/com_phpshop/toolbar.phpshop.html.php?mosConfig_absolute_path=
components/com_rsgallery/rsgallery.html.php?mosConfig_absolute_path=
components/com_simpleboard/image_upload.php?sbp=
Computer Science.asp?id=
Computer Science.php?id=
confidential site:mil
config.php
config.php?_CCFG[_PKG_PATH_DBSE]=
ConnectionTest.java filetype:html
constructies/product.asp?id=
constructies/product.php?id=
contact-us?reportCompany=
contact.asp?cartId=
contact.cfm?cartId=
contact.php?cartId=
contact.php?id=
contacts ext:wml
contact_details.php?id=
contenido.php?sec=
content.asp?arti_id=
content.asp?categoryId=
content.asp?cID=
content.asp?cid=
content.asp?cont_title=
content.asp?id=
content.asp?ID=
content.asp?p=
content.asp?PID=
content.cfm?id=
content.php?arti_id=
content.php?categoryId=
content.php?cID=
content.php?cid=
content.php?cont_title=
content.php?dtid=
content.php?id
content.php?id=
content.php?ID=
content.php?nID=
content.php?op=
content.php?p=
content.php?page=
content.php?PID=
content/conference_register.asp?ID=
content/conference_register.php?ID=
content/detail.asp?id=
content/detail.php?id=
content/index.asp?id=
content/index.php?id=
content/pages/index.asp?id_cat=
content/pages/index.php?id_cat=
content/programme.asp?ID=
content/programme.php?ID=
content/view.asp?id=
content/view.php?id=
contentok.php?id=
con_product.php?prodid=
coppercop/theme.php?THEME_DIR=
corporate/faqs/faq.php?Id=
corporate/newsreleases_more.asp?id=
corporate/newsreleases_more.php?id=
county-facts/diary/vcsgen.asp?id=
county-facts/diary/vcsgen.php?id=
courses/course-details.php?id=
courses/course.php?id=
cps/rde/xchg/tm/hs.xsl/liens_detail.html?lnkId=
cryolab/content.asp?cid=
cryolab/content.php?cid=
csc/news-details.asp?cat=
csc/news-details.php?cat=
cube/index.php?cat_id=
cubecart/index.php?cat_id=
cuisine/index.php?id=
current/diary/story.php?id=
customer/board.htm?mode=
customer/home.asp?cat=
customer/home.php?cat=
customer/product.php?productid=
customerService.asp?****ID1=
customerService.cfm?****ID1=
customerService.php?****ID1=
custompages.php?id=
CuteNews" "2003..2005 CutePHP"
c_page.php?id=
data filetype:mdb -site:gov -site:mil
dataaccess/article.php?ID=
db.php?path_local=
db/CART/product_details.asp?product_id=
db/CART/product_details.php?product_id=
db/item.html?item=
ddoecom/index.php?id=
ddoecom/product.php?proid=
de/content.asp?page_id=
de/content.php?page_id=
deal_coupon.asp?cat_id=
deal_coupon.php?cat_id=
debate-detail.asp?id=
debate-detail.php?id=
declaration_more.php?decl_id=
default.asp?catID=
default.asp?cPath=
default.asp?TID=
default.cfm?catID=
default.php?*root*=
default.php?abre=
default.php?basepath=
default.php?base_dir=
default.php?body=
default.php?catID=
default.php?channel=
default.php?chapter=
default.php?choix=
default.php?cmd=
default.php?cont=
default.php?cPath=
default.php?destino=
default.php?e=
default.php?eval=
default.php?f=
default.php?goto=
default.php?header=
default.php?inc=
default.php?incl=
default.php?include=
default.php?index=
default.php?ir=
default.php?itemnav=
default.php?k=
default.php?ki=
default.php?l=
default.php?left=
default.php?load=
default.php?loader=
default.php?loc=
default.php?m=
default.php?menu=
default.php?menue=
default.php?mid=
default.php?mod=
default.php?module=
default.php?n=
default.php?name=
default.php?nivel=
default.php?oldal=
default.php?opcion=
default.php?option=
default.php?p=
default.php?pa=
default.php?pag=
default.php?page=
default.php?pageweb=
default.php?panel=
default.php?param=
default.php?play=
default.php?pr=
default.php?pre=
default.php?read=
default.php?ref=
default.php?rub=
default.php?secao=
default.php?secc=
default.php?seccion=
default.php?seite=
default.php?showpage=
default.php?sivu=
default.php?sp=
default.php?str=
default.php?strona=
default.php?t=
default.php?thispage=
default.php?TID=
default.php?tipo=
default.php?to=
default.php?type=
default.php?v=
default.php?var=
default.php?x=
default.php?y=
description.asp?bookid=
description.cfm?bookid=
description.php?bookid=
designcenter/item.php?id=
detail.asp?id=
detail.asp?ID=
detail.asp?prodid=
detail.asp?prodID=
detail.asp?siteid=
detail.php?cat_id=
detail.php?id=
detail.php?ID=
detail.php?item_id=
detail.php?prodid=
detail.php?prodID=
detail.php?siteid=
detailedbook.asp?isbn=
detailedbook.php?isbn=
detailed_product.asp?id=
details.asp?BookID=
details.asp?id=
details.asp?Press_Release_ID=
details.asp?prodId=
details.asp?ProdID=
details.asp?prodID=
details.asp?Product_ID=
details.asp?Service_ID=
details.cfm?BookID=
details.cfm?Press_Release_ID=
details.cfm?Product_ID=
details.cfm?Service_ID=
details.php?BookID=
details.php?id=
details.php?page=
details.php?Press_Release_ID=
details.php?prodId=
details.php?ProdID=
details.php?prodID=
details.php?prodid=
details.php?Product_ID=
details.php?Service_ID=
details/food.php?cid=
developments_detail.php?id=
developments_view.php?id=
directory.php?cat=
directory/contenu.asp?id_cat=
directory/contenu.php?id_cat=
directory/listing_coupons.php?id=
directory/profile.php?id=
directory/showcat.php?cat=
directorylisting.php?cat=
discont_productpg.php?product_id=
discussions/10/9/?CategoryID=
discussions/9/6/?CategoryID=
display-product.php?Product=
display-sunsign.php?id=
display.asp?ID=
display.php?ID=
display.php?id=
displayArticle.php?id=
displayArticleB.asp?id=
displayArticleB.php?id=
displayproducts.asp
displayproducts.cfm
displayproducts.php
displayrange.asp?rangeid=
displayrange.php?rangeid=
display_item.asp?id=
display_item.cfm?id=
display_item.php?id=
display_page.asp?id=
display_page.php?elementId=
display_page.php?id=
display_page.php?tpl=
display_user.php?ID=
docDetail.aspx?chnum=
Doncaster/events/event.php?ID=
down*.php?action=
down*.php?addr=
down*.php?channel=
down*.php?choix=
down*.php?cmd=
down*.php?corpo=
down*.php?disp=
down*.php?doshow=
down*.php?ev=
down*.php?filepath=
down*.php?goFile=
down*.php?home=
down*.php?in=
down*.php?inc=
down*.php?incl=
down*.php?include=
down*.php?ir=
down*.php?lang=
down*.php?left=
down*.php?nivel=
down*.php?oldal=
down*.php?open=
down*.php?OpenPage=
down*.php?pa=
down*.php?pag=
down*.php?pageweb=
down*.php?param=
down*.php?path=
down*.php?pg=
down*.php?phpbb_root_path=
down*.php?pollname=
down*.php?pr=
down*.php?pre=
down*.php?qry=
down*.php?r=
down*.php?read=
down*.php?s=
down*.php?second=
down*.php?section=
down*.php?seite=
down*.php?showpage=
down*.php?sp=
down*.php?strona=
down*.php?subject=
down*.php?t=
down*.php?texto=
down*.php?to=
down*.php?u=
down*.php?url=
down*.php?v=
down*.php?where=
down*.php?x=
down*.php?z=
download.asp?id=
download.php?id=
downloads.asp?id=
downloads.asp?software=
downloads.php?file_id=
downloads.php?id=
downloads.php?type=
downloads/category.asp?c=
downloads/category.php?c=
downloads/shambler.asp?id=
downloads/shambler.php?id=
downloads_info.php?id=
downloadTrial.asp?intProdID=
downloadTrial.cfm?intProdID=
downloadTrial.php?intProdID=
download_details.php?id=
download_free.php?id=
dream_interpretation.php?id=
Duclassified" -site:duware.com "DUware All Rights reserved"
duclassmate" -site:duware.com
Dudirectory" -site:duware.com
dudownload" -site:duware.com
dump.php?bd_id=
DUpaypal" -site:duware.com
DWMail" password intitle:dwmail
earth/visitwcm_view.php?id=
earthactivity.cfm?id=
edatabase/home.asp?cat=
edatabase/home.php?cat=
edition.asp?area_id=
edition.php?area_id=
editProduct.php?cid=
education.php?id_cat=
education/content.asp?page=
education/content.php?page=
eggdrop filetype:user user
Elite Forum Version *.*"
els_/product/product.asp?id=
els_/product/product.php?id=
emailproduct.asp?itemid=
emailproduct.cfm?itemid=
emailproduct.php?itemid=
emailToFriend.asp?idProduct=
emailToFriend.cfm?idProduct=
emailToFriend.php?idProduct=
en/details.php?id=
en/main.asp?id=
en/main.php?id=
en/mobile_phone.php?ProdID=
en/news/fullnews.asp?newsid=
en/news/fullnews.php?newsid=
en/procurement/news-item.php?newsID=
en/product.php?proid=
en/produit.php?id=
en/publications.asp?id=
en/publications.php?id=
en/visit.php?id=
enable password | secret "current configuration" -intext:the
enc/content.php?Home_Path=
eng/board/view.php?id=
eng/rgboard/view.asp?&bbs_id=
eng/rgboard/view.php?&bbs_id=
eng/store/show_scat.php?cat_id=
english/board/view****.asp?code=
english/board/view****.php?code=
english/fonction/print.asp?id=
english/fonction/print.php?id=
english/gallery.php?id=
english/index.php?id=
english/print.asp?id=
english/print.php?id=
english/publicproducts.asp?groupid=
english/publicproducts.php?groupid=
eng_board/view.asp?T****=
eng_board/view.php?T****=
enter.php?a=
enter.php?abre=
enter.php?addr=
enter.php?b=
enter.php?base_dir=
enter.php?body=
enter.php?chapter=
enter.php?cmd=
enter.php?content=
enter.php?e=
enter.php?ev=
enter.php?get=
enter.php?go=
enter.php?goto=
enter.php?home=
enter.php?id=
enter.php?incl=
enter.php?include=
enter.php?index=
enter.php?ir=
enter.php?itemnav=
enter.php?lang=
enter.php?left=
enter.php?link=
enter.php?loader=
enter.php?menue=
enter.php?mid=
enter.php?middle=
enter.php?mod=
enter.php?module=
enter.php?name=
enter.php?numero=
enter.php?open=
enter.php?pa=
enter.php?page=
enter.php?pagina=
enter.php?panel=
enter.php?path=
enter.php?pg=
enter.php?phpbb_root_path=
enter.php?play=
enter.php?pname=
enter.php?pr=
enter.php?pref=
enter.php?qry=
enter.php?r=
enter.php?read=
enter.php?ref=
enter.php?s=
enter.php?sec=
enter.php?second=
enter.php?seite=
enter.php?sivu=
enter.php?sp=
enter.php?start=
enter.php?str=
enter.php?strona=
enter.php?subject=
enter.php?texto=
enter.php?thispage=
enter.php?type=
enter.php?viewpage=
enter.php?w=
enter.php?y=
entertainment/listings.php?id=
episode.php?id=
eshop.php?id=
estore/products.php?cat=
etc (index.of)
etemplate.php?id=
event.asp?id=
event.php?contentID=
event.php?id=
event/detail.php?id=
eventdetails.php?id=
events.asp?ID=
events.cfm?ID=
events.php?ID=
events.php?id=
events.php?pid=
events/detail.asp?ID=
events/detail.php?ID=
events/detail.php?id=
events/details.php?id=
events/event-detail.cfm?intNewsEventsID=
events/event.asp?id=
events/event.asp?ID=
events/event.php?id=
events/event.php?ID=
events/events.php?id=
events/event_detail.asp?id=
events/event_detail.php?id=
events/index.asp?id=
events/index.php?id=
events/index.php?ID=
events/unique_event.asp?ID=
events/unique_event.php?ID=
events?id=
eventsdetail.php?pid=
events_details.php?id=
events_more.php?id=
eventtype.php?id=
event_details.asp?id=
event_details.php?id=
event_info.asp?p=
event_info.php?p=
event_listings_short.php?s=
exclusive.php?pID=
exhibitions/detail.asp?id=
exhibitions/detail.php?id=
exhibitions/details.php?id=
exhibition_overview.asp?id=
exhibition_overview.php?id=
exported email addresses
ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:"budget approved") inurl:confidential
ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:”budget approved”) inurl:confidential
ext:asa | ext:bak intext:uid intext:pwd -"uid..pwd" database | server | dsn
ext:asp inurl:pathto.asp
ext:ccm ccm -catacomb
ext:CDX CDX
ext:cfg radius.cfg
ext:cgi intext:"nrg-" " This web page was created on "
ext:cgi intitle:"control panel" "enter your owner password to continue!"
ext:cgi inurl:editcgi.cgi inurl:file=
ext:conf inurl:rsyncd.conf -cvs -man
ext:conf NoCatAuth -cvs
ext:dat bpk.dat
ext:gho gho
ext:ics ics
ext:inc "pwd=" "UID="
ext:ini eudora.ini
ext:ini intext:env.ini
ext:ini Version=... password
ext:ini Version=4.0.0.4 password
ext:jbf jbf
ext:ldif ldif
ext:log "Software: Microsoft Internet Information
ext:log "Software: Microsoft Internet Information Services *.*"
ext:log "Software: Microsoft Internet Information Services _._"
ext:log \"Software: Microsoft Internet Information Services _._\"
ext:mdb inurl:*.mdb inurl:fpdb shop.mdb
ext:mdb inurl:_.mdb inurl:fpdb shop.mdb
ext:nsf nsf -gov -mil
ext:passwd -intext:the -sample -example
ext:php intitle:phpinfo "published by the PHP Group"
ext:php | intitle:phpinfo \"published by the PHP Group\"
ext:plist filetype:plist inurl:bookmarks.plist
ext:pqi pqi -database
ext:pwd inurl:(service | authors | administrators | users) "# -FrontPage-"
ext:reg "username=*" putty
ext:sql | ext:txt intext:"-- phpMyAdmin SQL Dump --" + intext:"admin"
ext:txt "Final encryption key"
ext:txt inurl:dxdiag
ext:txt inurl:unattend.txt
ext:txt | ext:log | ext:cfg "Building configuration..."
ext:txt | ext:log | ext:cfg | ext:yml "administrator:500:"
ext:vmdk vmdk
ext:vmx vmx
ext:yml database inurl:config
ext:yml | ext:txt | ext:env "Database Connection Information Database server ="
extensions/extlist.php?cat=
ez Publish administration
e_board/modifyform.html?code=
faq.asp?cartID=
faq.cfm?cartID=
faq.php?****=
faq.php?cartID=
faq.php?id=
faq.php?q_id=
faq/category.php?id=
faq/question.php?Id=
faq2.php?id=
FaqDetail.php?ID=
faqs.asp?id=
faqs.cfm?id=
faqs.php?id=
faq_list.asp?id=
faq_list.cfm?id=
faq_list.php?id=
fatcat/artistInfo.php?id=
fatcat/home.asp?view=
fatcat/home.php?view=
fcms/view.php?cid=
feature.asp?id=
feature.php?id=
feature2.php?id=
featuredetail.php?id=
Featured_Site.php?id=
features/view.php?id=
feedback.asp?title=
feedback.cfm?title=
feedback.php?title=
fellows.php?id=
FernandFaerie/index.asp?c=
FernandFaerie/index.php?c=
ficha.php?id=
fiche_spectacle.php?id=
Fichier contenant des informations sur le r?seau :
file.php?action=
file.php?basepath=
file.php?body=
file.php?channel=
file.php?chapter=
file.php?choix=
file.php?cmd=
file.php?cont=
file.php?corpo=
file.php?disp=
file.php?doshow=
file.php?ev=
file.php?eval=
file.php?get=
file.php?id=
file.php?inc=
file.php?incl=
file.php?include=
file.php?index=
file.php?ir=
file.php?ki=
file.php?left=
file.php?load=
file.php?loader=
file.php?middle=
file.php?modo=
file.php?n=
file.php?nivel=
file.php?numero=
file.php?oldal=
file.php?pagina=
file.php?param=
file.php?pg=
file.php?play=
file.php?pollname=
file.php?pref=
file.php?q=
file.php?qry=
file.php?ref=
file.php?seccion=
file.php?second=
file.php?showpage=
file.php?sivu=
file.php?sp=
file.php?start=
file.php?strona=
file.php?texto=
file.php?to=
file.php?type=
file.php?url=
file.php?var=
file.php?viewpage=
file.php?where=
file.php?y=
filemanager.php?delete=
files.php?cat=
filetype:asp "Custom Error Message" Category Source
filetype:asp + "[ODBC SQL"
filetype:ASP ASP
filetype:asp DBQ=" * Server.MapPath("*.mdb")
filetype:asp DBQ=" _ Server.MapPath("_.mdb")
filetype:asp DBQ=\" _ Server.MapPath(\"_.mdb\")
filetype:asp “Custom Error Message” Category Source
filetype:ASPX ASPX
filetype:bak createobject sa
filetype:bak inurl:"htaccess|passwd|shadow|htusers"
filetype:bak inurl:\"htaccess|passwd|shadow|htusers\"
filetype:bkf bkf
filetype:blt "buddylist"
filetype:blt blt +intext:screenname
filetype:BML BML
filetype:cfg auto_inst.cfg
filetype:cfg ks intext:rootpw -sample -test -howto
filetype:cfg mrtg "target
filetype:cfm "cfapplication name" password
filetype:CFM CFM
filetype:CGI CGI
filetype:cgi inurl:"fileman.cgi"
filetype:cgi inurl:"Web_Store.cgi"
filetype:cnf inurl:_vti_pvt access.cnf
filetype:conf inurl:firewall -intitle:cvs
filetype:conf inurl:proftpd. PROFTP FTP server configuration file reveals
filetype:conf inurl:psybnc.conf "USER.PASS="
filetype:conf oekakibbs
filetype:conf slapd.conf
filetype:config config intext:appSettings "User ID"
filetype:config inurl:web.config inurl:ftp
filetype:config web.config -CVS
filetype:ctt Contact
filetype:ctt ctt messenger
filetype:dat "password.dat
filetype:dat "password.dat"
filetype:dat inurl:Sites.dat
filetype:dat wand.dat
filetype:dat \"password.dat\"
filetype:DIFF DIFF
filetype:DLL DLL
filetype:DOC DOC
filetype:eml eml +intext:"Subject" +intext:"From" +intext:"To"
filetype:eml eml +intext:\"Subject\" +intext:\"From\" +intext:\"To\"
filetype:eml eml +intext:”Subject” +intext:”From” +intext:”To”
filetype:FCGI FCGI
filetype:fp3 fp3
filetype:fp5 fp5 -site:gov -site:mil -"cvs log"
filetype:fp7 fp7
filetype:HTM HTM
filetype:HTML HTML
filetype:inc dbconn
filetype:inc intext:mysql*connect
filetype:inc intext:mysql_connect
filetype:inc mysql_connect OR mysql_pconnect
filetype:inf inurl:capolicy.inf
filetype:inf sysprep
filetype:ini inurl:"serv-u.ini"
filetype:ini inurl:flashFXP.ini
filetype:ini ServUDaemon
filetype:ini wcx_ftp
filetype:ini ws_ftp pwd
filetype:JHTML JHTML
filetype:JSP JSP
filetype:ldb admin
filetype:lic lic intext:key
filetype:log "PHP Parse error" | "PHP Warning" | "PHP Error"
filetype:log "See `ipsec --copyright"
filetype:log access.log -CVS
filetype:log cron.log
filetype:log intext:"ConnectionManager2"
filetype:log inurl:"password.log"
filetype:log inurl:password.log
filetype:log username putty PUTTY SSH client logs can reveal usernames
filetype:log “PHP Parse error” | “PHP Warning” | “PHP Error”
filetype:mbx mbx intext:Subject
filetype:mdb inurl:users.mdb
filetype:mdb wwforum
filetype:MV MV
filetype:myd myd -CVS
filetype:netrc password
filetype:ns1 ns1
filetype:ora ora
filetype:ora tnsnames
filetype:pass pass intext:userid
filetype:pdb pdb backup (Pilot | Pluckerdb)
filetype:pdf "Assessment Report" nessus
filetype:PDF PDF
filetype:pem intext:private
filetype:php inurl:"logging.php" "Discuz" error
filetype:php inurl:"webeditor.php"
filetype:php inurl:index inurl:phpicalendar -site:sourceforge.net
filetype:php inurl:ipinfo.php "Distributed Intrusion Detection System"
filetype:php inurl:nqt intext:"Network Query Tool"
filetype:php inurl:vAuthenticate
filetype:PHP PHP
filetype:PHP3 PHP3
filetype:PHP4 PHP4
filetype:PHTML PHTML
filetype:pl "Download: SuSE Linux Openexchange Server CA"
filetype:pl intitle:"Ultraboard Setup"
filetype:PL PL
filetype:pot inurl:john.pot
filetype:PPT PPT
filetype:properties inurl:db intext:password
filetype:PS ps
filetype:PS PS
filetype:pst inurl:"outlook.pst"
filetype:pst pst -from -to -date
filetype:pwd service
filetype:pwl pwl
filetype:qbb qbb
filetype:QBW qbw
filetype:r2w r2w
filetype:rdp rdp
filetype:reg "Terminal Server Client"
filetype:reg reg +intext:"defaultusername" +intext:"defaultpassword"
filetype:reg reg +intext:\"defaultusername\" +intext:\"defaultpassword\"
filetype:reg reg +intext:â? WINVNC3â?
filetype:reg reg +intext:Ã¢? WINVNC3Ã¢?
filetype:reg reg +intext:”defaultusername” +intext:”defaultpassword”
filetype:reg reg HKEY* Windows Registry exports can reveal
filetype:reg reg HKEY_CURRENT_USER SSHHOSTKEYS
filetype:SHTML SHTML
filetype:sql "insert into" (pass|passwd|password)
filetype:sql ("values * MD5" | "values * password" | "values * encrypt")
filetype:sql ("values _ MD5" | "values _ password" | "values _ encrypt")
filetype:sql (\"passwd values\" | \"password values\" | \"pass values\" )
filetype:sql (\"values _ MD\" | \"values _ password\" | \"values _ encrypt\")
filetype:sql +"IDENTIFIED BY" -cvs
filetype:sql password
filetype:sql “insert into” (pass|passwd|password)
filetype:STM STM
filetype:SWF SWF
filetype:TXT TXT
filetype:url +inurl:"ftp://" +inurl:";@"
filetype:url +inurl:\"ftp://\" +inurl:\";@\"
filetype:url +inurl:”ftp://” +inurl:”;@”
filetype:vcs vcs
filetype:vsd vsd network -samples -examples
filetype:wab wab
filetype:xls -site:gov inurl:contact
filetype:xls inurl:"email.xls"
filetype:xls username password email
filetype:XLS XLS
films.php?id=
finalrevdisplay.php?id=
Financial spreadsheets: finance.xls
Financial spreadsheets: finances.xls
fitxa.php?id=
folder.php?id=
fonts/details.php?id=
forum.php?act=
forum/index.php?topic=
forum/profile.asp?id=
forum/profile.php?id=
forum/showProfile.asp?id=
forum/showProfile.php?id=
forum/showthread.php?p=
forum/showthread.php?t=
forum/viewtopic.php?id=
forum/viewtopic.php?t=
forum/viewtopic.php?TopicID=
forumapc/plantfinder/details.php?id=
forums/index.php?page=
forums/index.php?topic=
forums/search.php?do=
forums/showthread.php?t=
forum_bds.php?num=
fr/commande-liste-categorie.asp?panier=
fr/commande-liste-categorie.php?panier=
franchise2.php?id=
free-release.php?id=
FREE/poll.php?pid=
freedownload.asp?bookid=
freedownload.cfm?bookid=
freedownload.php?bookid=
free_board/board_view.html?page=
frf10/news.php?id=
front/bin/forumview.phtml?bbcode=
frontend/category.asp?id_category=
frontend/category.php?id_category=
fshstatistic/index.asp?PID=
fshstatistic/index.php?&PID=
fshstatistic/index.php?PID=
fullDisplay.asp?item=
fullDisplay.cfm?item=
fullDisplay.php?item=
FullStory.asp?Id=
FullStory.php?Id=
galerie.asp?cid=
galerie.php?cid=
Gallery in configuration mode
gallery.asp?id=
gallery.php?*[*]*=
gallery.php?abre=
gallery.php?action=
gallery.php?addr=
gallery.php?basepath=
gallery.php?base_dir=
gallery.php?chapter=
gallery.php?cont=
gallery.php?corpo=
gallery.php?disp=
gallery.php?ev=
gallery.php?eval=
gallery.php?filepath=
gallery.php?get=
gallery.php?go=
gallery.php?h=
gallery.php?id=
gallery.php?index=
gallery.php?itemnav=
gallery.php?ki=
gallery.php?left=
gallery.php?loader=
gallery.php?menu=
gallery.php?menue=
gallery.php?mid=
gallery.php?mod=
gallery.php?module=
gallery.php?my=
gallery.php?name=
gallery.php?nivel=
gallery.php?oldal=
gallery.php?open=
gallery.php?option=
gallery.php?pag=
gallery.php?page=
gallery.php?pageweb=
gallery.php?panel=
gallery.php?param=
gallery.php?pg=
gallery.php?phpbb_root_path=
gallery.php?pname=
gallery.php?pollname=
gallery.php?pre=
gallery.php?pref=
gallery.php?qry=
gallery.php?redirect=
gallery.php?ref=
gallery.php?rub=
gallery.php?sec=
gallery.php?secao=
gallery.php?seccion=
gallery.php?seite=
gallery.php?showpage=
gallery.php?sivu=
gallery.php?sp=
gallery.php?strona=
gallery.php?thispage=
gallery.php?tipo=
gallery.php?to=
gallery.php?url=
gallery.php?var=
gallery.php?viewpage=
gallery.php?where=
gallery.php?xlink=
gallery.php?y=
gallery/categoria.php?id_cat=
gallery/detail.asp?ID=
gallery/detail.php?ID=
gallery/gallery.asp?id=
gallery/gallery.php?id=
gallery/mailmanager/subscribe.php?ID=
gallerysort.asp?iid=
gallerysort.php?iid=
game.php?id=
games.php?id=
games/index.php?task=
games/play.php?id=
Ganglia Cluster Reports
garden_equipment/Fruit-Cage/product.asp?pr=
garden_equipment/Fruit-Cage/product.php?pr=
garden_equipment/pest-weed-control/product.asp?pr=
garden_equipment/pest-weed-control/product.php?pr=
gb/comment.asp?gb_id=
gb/comment.php?gb_id=
general.asp?id=
general.php?abre=
general.php?addr=
general.php?adresa=
general.php?b=
general.php?base_dir=
general.php?body=
general.php?channel=
general.php?chapter=
general.php?choix=
general.php?cmd=
general.php?content=
general.php?doshow=
general.php?e=
general.php?f=
general.php?get=
general.php?goto=
general.php?header=
general.php?id=
general.php?inc=
general.php?include=
general.php?ir=
general.php?itemnav=
general.php?left=
general.php?link=
general.php?menu=
general.php?menue=
general.php?mid=
general.php?middle=
general.php?modo=
general.php?module=
general.php?my=
general.php?name=
general.php?nivel=
general.php?opcion=
general.php?p=
general.php?page=
general.php?pageweb=
general.php?pollname=
general.php?pr=
general.php?pre=
general.php?qry=
general.php?read=
general.php?redirect=
general.php?ref=
general.php?rub=
general.php?secao=
general.php?seccion=
general.php?second=
general.php?section=
general.php?seite=
general.php?sekce=
general.php?sivu=
general.php?strona=
general.php?subject=
general.php?texto=
general.php?thispage=
general.php?tipo=
general.php?to=
general.php?type=
general.php?var=
general.php?w=
general.php?where=
general.php?xlink=
general/blogpost/?p=
getbook.asp?bookid=
getbook.cfm?bookid=
getbook.php?bookid=
GetItems.asp?itemid=
GetItems.cfm?itemid=
GetItems.php?itemid=
giftDetail.asp?id=
giftDetail.cfm?id=
giftDetail.php?id=
giftshop/product.php?proid=
gig.asp?id=
gig.php?id=
global/product/product.asp?gubun=
global/product/product.php?gubun=
global_projects.asp?cid=
global_projects.php?cid=
gnu/?doc=
goboard/front/board_view.asp?code=
goboard/front/board_view.php?code=
goods_detail.asp?data=
goods_detail.php?data=
goods_detail.php?goodsIdx=
goto.php?area_id=
GT5/car-details.php?id=
h4kurd/showthread.php?tid=
haccess.ctl (one way)
haccess.ctl (VERY reliable)
hall.php?file=
hall.php?page=
Hassan Consulting's Shopping Cart Version 1.18
head.php?*[*]*=
head.php?abre=
head.php?adresa=
head.php?b=
head.php?base_dir=
head.php?c=
head.php?choix=
head.php?cmd=
head.php?content=
head.php?corpo=
head.php?d=
head.php?dir=
head.php?disp=
head.php?ev=
head.php?filepath=
head.php?g=
head.php?goto=
head.php?inc=
head.php?incl=
head.php?include=
head.php?index=
head.php?ir=
head.php?ki=
head.php?lang=
head.php?left=
head.php?load=
head.php?loader=
head.php?loc=
head.php?middle=
head.php?middlePart=
head.php?mod=
head.php?modo=
head.php?module=
head.php?numero=
head.php?oldal=
head.php?opcion=
head.php?pag=
head.php?pageweb=
head.php?play=
head.php?pname=
head.php?pollname=
head.php?read=
head.php?ref=
head.php?rub=
head.php?sec=
head.php?sekce=
head.php?sivu=
head.php?start=
head.php?str=
head.php?strona=
head.php?tipo=
head.php?viewpage=
head.php?where=
head.php?y=
hearst_journalism/press_release.php?id=
help.asp?CartId=
help.cfm?CartId=
help.php?CartId=
help.php?css_path=
help/com_view.html?code=
historialeer.php?num=
historical/stock.php?symbol=
history/index.php?id=
HistoryStore/pages/item.asp?itemID=
HistoryStore/pages/item.php?itemID=
hm/inside.asp?id=
hm/inside.php?id=
holidays/dest/offers/offers.php?id=
home.asp?cat=
home.asp?id=
home.asp?ID=
home.cfm?id=
home.php?a=
home.php?action=
home.php?addr=
home.php?basepath=
home.php?base_dir=
home.php?body=
home.php?cat=
home.php?category=
home.php?channel=
home.php?chapter=
home.php?choix=
home.php?cmd=
home.php?content=
home.php?disp=
home.php?doshow=
home.php?e=
home.php?ev=
home.php?eval=
home.php?g=
home.php?h=
home.php?id=
home.php?ID=
home.php?in=
home.php?include=
home.php?index=
home.php?ir=
home.php?itemnav=
home.php?k=
home.php?link=
home.php?loader=
home.php?loc=
home.php?menu=
home.php?middle=
home.php?middlePart=
home.php?module=
home.php?my=
home.php?oldal=
home.php?opcion=
home.php?pa=
home.php?page=
home.php?pageweb=
home.php?pagina=
home.php?panel=
home.php?path=
home.php?play=
home.php?pollname=
home.php?pr=
home.php?pre=
home.php?qry=
home.php?read=
home.php?recipe=
home.php?redirect=
home.php?ref=
home.php?rub=
home.php?sec=
home.php?secao=
home.php?section=
home.php?seite=
home.php?sekce=
home.php?showpage=
home.php?sp=
home.php?str=
home.php?thispage=
home.php?tipo=
home.php?w=
home.php?where=
home.php?x=
home.php?z=
homepage.php?sel=
hosting_info.php?id=
ht://Dig htsearch error
htm/item_cat.php?item_id=
html/101_artistInfo.php?id=
html/gallery.php?id=
html/home/products/product.php?pid=
html/print.asp?sid=
html/print.php?sid=
html/products.php?id=
html/products_cat.php?cat_id=
html/projdetail.php?id=
html/scoutnew.asp?prodid=
html/scoutnew.php?prodid=
htmlpage.asp?id=
htmlpage.php?id=
htmltonuke.php?filnavn=
htpasswd
htpasswd / htgroup
htpasswd / htpasswd.bak
humor.php?id=
hw_reviews.php?id=
i-know/content.asp?page=
i-know/content.php?page=
iam/tabbedWithShowcase.php?pid=
ibp.asp?ISBN=
ibp.php?ISBN=
ICQ chat logs, please...
idlechat/message.asp?id=
idlechat/message.php?id=
ihm.php?p=
IIS 4.0 error messages
IIS web server error messages
IlohaMail"
impex/ImpExData.php?systempath=
inc/cmses/aedating4CMS.php?dir[inc]=
inc/cmses/aedating4CMS.php?dir[inc]= inurl:flashchat site:br bp_ncom.php?bnrep=
inc/cmses/aedatingCMS.php?dir[inc]=
inc/functions.inc.php?config[ppa_root_path]=
inc/header.php/step_one.php?server_inc=
inc/pipe.php?HCL_path=
include.php?*[*]*=
include.php?adresa=
include.php?b=
include.php?basepath=
include.php?channel=
include.php?chapter=
include.php?cmd=
include.php?cont=
include.php?content=
include.php?corpo=
include.php?destino=
include.php?dir=
include.php?eval=
include.php?filepath=
include.php?go=
include.php?goFile=
include.php?goto=
include.php?header=
include.php?in=
include.php?include=
include.php?index=
include.php?ir=
include.php?ki=
include.php?left=
include.php?loader=
include.php?loc=
include.php?mid=
include.php?middle=
include.php?middlePart=
include.php?module=
include.php?my=
include.php?name=
include.php?nivel=
include.php?numero=
include.php?oldal=
include.php?option=
include.php?pag=
include.php?pageweb=
include.php?panel=
include.php?path=
include.php?phpbb_root_path=
include.php?play=
include.php?read=
include.php?redirect=
include.php?ref=
include.php?sec=
include.php?secao=
include.php?seccion=
include.php?second=
include.php?sivu=
include.php?tipo=
include.php?to=
include.php?u=
include.php?url=
include.php?w=
include.php?x=
include/editfunc.inc.php?NWCONF_SYSTEM[server_path]=
include/new-visitor
include/new-visitor.inc.php?lvc_include_dir=
include/write.php?dir=
includes/functions.php?phpbb_root_path=
includes/header.php?systempath=
includes/search.php?GlobalSettings[templatesDirectory]=
includes/top-ten/display_review.php?id=
indepth/details.php?id=
Index of /_vti_pvt +"*.pwd"
Index of phpMyAdmin
index of: intext:Gallery in Configuration mode
index.asp/en/component/pvm/?view=
index.asp?action=
index.asp?area_id=
index.asp?book=
index.asp?cart=
index.asp?cartID=
index.asp?cat=
index.asp?cid=
index.asp?cPath=
index.asp?i=
index.asp?ID=
index.asp?id=
index.asp?lang=
index.asp?modus=
index.asp?news=
index.asp?offs=
index.asp?option=
index.asp?page=
index.asp?pageid=
index.asp?pageId=
index.asp?pagina=
index.asp?pg_t=
index.asp?pid=
index.asp?section=
index.asp?site=
index.asp?t=
index.asp?url=
index.asp?w=
index.cfm?cart=
index.cfm?cartID=
index.cfm?ID=
index.of passlist
index.of perform.ini mIRC IRC ini file can list IRC usernames and
index.of.dcim
index.of.password
index.php/en/component/pvm/?view=
index.php?=
index.php?a=
index.php?act=
index.php?action=
index.php?addr=
index.php?adresa=
index.php?area_id=
index.php?arquivo=
index.php?b=
index.php?basepath=
index.php?base_dir=
index.php?body=
index.php?book=
index.php?c=
index.php?canal=
index.php?cart=
index.php?cartID=
index.php?cat=
index.php?cat_id=
index.php?channel=
index.php?chapter=
index.php?cid=
index.php?cmd=
index.php?coment=
index.php?configFile=
index.php?cont=
index.php?content=
index.php?conteudo=
index.php?cPath=
index.php?dept=
index.php?disp=
index.php?do=
index.php?doc=
index.php?dsp=
index.php?ev=
index.php?file=
index.php?filepath=
index.php?go=
index.php?goto=
index.php?i=
index.php?ID=
index.php?id=
index.php?Id=
index.php?id_cat=
index.php?inc=
index.php?incl=
index.php?include=
index.php?index=
index.php?inhalt=
index.php?j=
index.php?kobr=
index.php?l=
index.php?lang=
index.php?lang=gr&file
index.php?langc=
index.php?Language=
index.php?lg=
index.php?link=
index.php?list=
index.php?load=
index.php?Load=
index.php?loc=
index.php?m=
index.php?main=
index.php?meio.php=
index.php?meio=
index.php?menu=
index.php?menu=deti&page=
index.php?mid=
index.php?middlePart=
index.php?mode=
index.php?modo=
index.php?module=
index.php?modus=
index.php?mwa=
index.php?news=
index.php?nic=
index.php?offs=
index.php?oldal=
index.php?op=
index.php?opcao=
index.php?opcion=
index.php?open=
index.php?openfile=
index.php?option=
index.php?ort=
index.php?p=
index.php?pag=
index.php?page=
index.php?pageid=
index.php?pageId=
index.php?pagename=
index.php?pageurl=
index.php?pagina=
index.php?param=
index.php?path=
index.php?pg=
index.php?pg_t=
index.php?pid=
index.php?pilih=
index.php?place=
index.php?play=
index.php?pname=
index.php?pollname=
index.php?pr=
index.php?pre=
index.php?pref=
index.php?principal=
index.php?product=
index.php?r=
index.php?rage=
index.php?recipe=
index.php?RP_PATH=
index.php?screen=
index.php?secao=
index.php?section=
index.php?sekce=
index.php?sel=
index.php?show=
index.php?showtopic=
index.php?side=
index.php?site=
index.php?sivu=
index.php?size=
index.php?str=
index.php?stranica=
index.php?strona=
index.php?sub=
index.php?sub=index.php?id=index.php?t=
index.php?t=
index.php?template=
index.php?tipo=
index.php?to=
index.php?topic=
index.php?type=
index.php?u=
index.php?u=administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php?mosConfig_absolute_path=
index.php?url=
index.php?var=
index.php?visualizar=
index.php?w=
index.php?where=
index.php?x=
index.php?x= index.php?mode=index.php?stranica=
index.php?y=
index.php?_REQUEST=&_REQUEST%5boption%5d=com_content&_REQUEST%5bItemid%5d=1&GLOBALS=&mosConfig_absolute_path=
index.phpmain.php?x=
index0.php?show=
index1.php?*root*=
index1.php?*[*]*=
index1.php?=
index1.php?abre=
index1.php?action=
index1.php?adresa=
index1.php?b=
index1.php?body=
index1.php?c=
index1.php?chapter=
index1.php?choix=
index1.php?cmd=
index1.php?d=
index1.php?dat=
index1.php?dir=
index1.php?filepath=
index1.php?get=
index1.php?go=
index1.php?goFile=
index1.php?home=
index1.php?incl=
index1.php?itemnav=
index1.php?l=
index1.php?link=
index1.php?load=
index1.php?loc=
index1.php?menu=
index1.php?mod=
index1.php?modo=
index1.php?my=
index1.php?nivel=
index1.php?o=
index1.php?oldal=
index1.php?op=
index1.php?OpenPage=
index1.php?pa=
index1.php?pagina=
index1.php?param=
index1.php?path=
index1.php?pg=
index1.php?pname=
index1.php?pollname=
index1.php?pr=
index1.php?pre=
index1.php?qry=
index1.php?read=
index1.php?recipe=
index1.php?redirect=
index1.php?second=
index1.php?seite=
index1.php?sekce=
index1.php?showpage=
index1.php?site=
index1.php?str=
index1.php?strona=
index1.php?subject=
index1.php?t=
index1.php?texto=
index1.php?tipo=
index1.php?type=
index1.php?url=
index1.php?v=
index1.php?var=
index1.php?x=
index2.php?action=
index2.php?adresa=
index2.php?ascii_seite=
index2.php?basepath=
index2.php?base_dir=
index2.php?category=
index2.php?channel=
index2.php?chapter=
index2.php?choix=
index2.php?cmd=
index2.php?content=
index2.php?corpo=
index2.php?d=
index2.php?DoAction=
index2.php?doshow=
index2.php?e=
index2.php?f=
index2.php?filepath=
index2.php?get=
index2.php?goto=
index2.php?home=
index2.php?ID=
index2.php?in=
index2.php?inc=
index2.php?incl=
index2.php?include=
index2.php?ir=
index2.php?itemnav=
index2.php?ki=
index2.php?left=
index2.php?link=
index2.php?load=
index2.php?loader=
index2.php?loc=
index2.php?module=
index2.php?my=
index2.php?oldal=
index2.php?open=
index2.php?OpenPage=
index2.php?option=
index2.php?p=
index2.php?pa=
index2.php?param=
index2.php?pg=
index2.php?phpbb_root_path=
index2.php?pname=
index2.php?pollname=
index2.php?pre=
index2.php?pref=
index2.php?qry=
index2.php?recipe=
index2.php?redirect=
index2.php?ref=
index2.php?rub=
index2.php?second=
index2.php?section=
index2.php?sekce=
index2.php?showpage=
index2.php?strona=
index2.php?texto=
index2.php?thispage=
index2.php?to=
index2.php?type=
index2.php?u=
index2.php?url_page=
index2.php?var=
index2.php?x=
index3.php?abre=
index3.php?addr=
index3.php?adresa=
index3.php?base_dir=
index3.php?body=
index3.php?channel=
index3.php?chapter=
index3.php?choix=
index3.php?cmd=
index3.php?d=
index3.php?destino=
index3.php?dir=
index3.php?disp=
index3.php?ev=
index3.php?get=
index3.php?go=
index3.php?home=
index3.php?inc=
index3.php?include=
index3.php?index=
index3.php?ir=
index3.php?itemnav=
index3.php?left=
index3.php?link=
index3.php?loader=
index3.php?menue=
index3.php?mid=
index3.php?middle=
index3.php?mod=
index3.php?my=
index3.php?name=
index3.php?nivel=
index3.php?oldal=
index3.php?open=
index3.php?option=
index3.php?p=
index3.php?pag=
index3.php?pageweb=
index3.php?panel=
index3.php?path=
index3.php?phpbb_root_path=
index3.php?pname=
index3.php?pollname=
index3.php?pre=
index3.php?pref=
index3.php?q=
index3.php?read=
index3.php?redirect=
index3.php?ref=
index3.php?rub=
index3.php?secao=
index3.php?secc=
index3.php?seccion=
index3.php?second=
index3.php?sekce=
index3.php?showpage=
index3.php?sivu=
index3.php?sp=
index3.php?start=
index3.php?t=
index3.php?thispage=
index3.php?tipo=
index3.php?type=
index3.php?url=
index3.php?var=
index3.php?x=
index3.php?xlink=
index_en.asp?id=
index_en.asp?ref=
index_en.php?id=
index_en.php?ref=
index_principal.php?pagina=
info.asp?ID=
info.cfm?ID=
info.php?*[*]*=
info.php?adresa=
info.php?base_dir=
info.php?body=
info.php?c=
info.php?chapter=
info.php?content=
info.php?doshow=
info.php?ev=
info.php?eval=
info.php?f=
info.php?filepath=
info.php?go=
info.php?header=
info.php?home=
info.php?ID=
info.php?id=
info.php?in=
info.php?incl=
info.php?ir=
info.php?itemnav=
info.php?j=
info.php?ki=
info.php?l=
info.php?loader=
info.php?menue=
info.php?mid=
info.php?middlePart=
info.php?o=
info.php?oldal=
info.php?op=
info.php?opcion=
info.php?option=
info.php?pageweb=
info.php?pagina=
info.php?param=
info.php?phpbb_root_path=
info.php?pname=
info.php?pref=
info.php?r=
info.php?read=
info.php?recipe=
info.php?redirect=
info.php?ref=
info.php?rub=
info.php?sec=
info.php?secao=
info.php?seccion=
info.php?start=
info.php?strona=
info.php?subject=
info.php?t=
info.php?texto=
info.php?url=
info.php?var=
info.php?xlink=
info.php?z=
infusions/book_panel/books.php?bookid=
install/index.php?lng=../../include/main.inc&G_PATH=
Interior/productlist.asp?id=
Interior/productlist.php?id=
interna/tiny_mce/plugins/ibrowser/ibrowser.php?tinyMCE_imglib_include=
Internal Server Error
intext:" -FrontPage-" ext:pwd inurl:(service | authors | administrators | users)
intext:""BiTBOARD v2.0" BiTSHiFTERS Bulletin Board"
intext:"# -FrontPage-" ext:pwd inurl:(service | authors | administrators | users) "# -FrontPage-" inurl:service.pwd
intext:"#mysql dump" filetype:sql
intext:"#mysql dump" filetype:sql 21232f297a57a5a743894a0e4a801fc3
intext:"A syntax error has occurred" filetype:ihtml
intext:"About Mac OS Personal Web Sharing"
intext:"An illegal character has been found in the statement" -"previous message"
intext:"ASP.NET_SessionId" "data source="
intext:"AutoCreate=TRUE password=_"
intext:"Can't connect to local" intitle:warning
intext:"Certificate Practice Statement" filetype:PDF | DOC
intext:"Certificate Practice Statement" inurl:(PDF | DOC)
intext:"Connection" AND "Network name" AND " Cisco Meraki cloud" AND "Security Appliance details"
intext:"Copyright (c) Tektronix, Inc." "printer status"
intext:"Copyright © Tektronix, Inc." "printer status"
intext:"d.aspx?id" || inurl:"d.aspx?id"
intext:"Emergisoft web applications are a part of our"
intext:"enable password 7"
intext:"enable secret 5 $"
intext:"Error Diagnostic Information" intitle:"Error Occurred While"
intext:"Error Message : Error loading required libraries."
intext:"Establishing a secure Integrated Lights Out session with" OR intitle:"Data Frame - Browser not HTTP 1.1 compatible" OR intitle:"HP Integrated Lights-
intext:"EZGuestbook"
intext:"Fatal error: Call to undefined function" -reply -the -next
intext:"Fill out the form below completely to change your password and user name. If new username is left blank, your old one will be assumed." -edu
intext:"Generated by phpSystem"
intext:"Healthy" + "Product model" + " Client IP" + "Ethernet"
intext:"Host Vulnerability Summary Report"
intext:"HostingAccelerator" intitle:"login" +"Username" -"news" -demo
intext:"IMail Server Web Messaging" intitle:login
intext:"Incom CMS 2.0"
intext:"Incorrect syntax near"
intext:"Index of /" +.htaccess
intext:"Index of /" +passwd
intext:"Index of /" +password.txt
intext:"Index of /admin"
intext:"Index of /backup"
intext:"Index of /mail"
intext:"Index of /network" "last modified"
intext:"Index of /password"
intext:"Index of" /"chat/logs"
intext:"Mail admins login here to administrate your domain."
intext:"Master Account" "Domain Name" "Password" inurl:/cgi-bin/qmailadmin
intext:"Microsoft (R) Windows _ (TM) Version _ DrWtsn32 Copyright (C)" ext:log
intext:"Microsoft CRM : Unsupported Browser Version"
intext:"Microsoft ® Windows _ ™ Version _ DrWtsn32 Copyright ©" ext:log
intext:"Network Host Assessment Report" "Internet Scanner"
intext:"Network Vulnerability Assessment Report"
intext:"Network Vulnerability Assessment Report" 本文来自 pc007.com
intext:"phpMyAdmin MySQL-Dump" "INSERT INTO" -"the"
intext:"phpMyAdmin MySQL-Dump" filetype:txt
intext:"phpMyAdmin" "running on" inurl:"main.php"
intext:"Powered By : SE Software Technologies" filetype:php
intext:"powered by Web Wiz Journal"
intext:"Session Start * * * *:*:* *" filetype:log
intext:"SonarQube" + "by SonarSource SA." + "LGPL v3"
intext:"SQL Server Driver][SQL Server]Line 1: Incorrect syntax near"
intext:"SteamUserPassphrase=" intext:"SteamAppUser=" -"username" -"user"
intext:"Storage Management Server for" intitle:"Server Administration"
intext:"Thank you for your order" +receipt
intext:"Thank you for your purchase" +download
intext:"The following report contains confidential information" vulnerability -search
intext:"Tobias Oetiker" "traffic analysis"
intext:"user name" intext:"orion core" -solarwinds.com
intext:"vbulletin" inurl:admincp
intext:"Warning: * am able * write ** configuration file" "includes/configure.php" -
intext:"Warning: Failed opening" "on line" "include_path"
intext:"Web Wiz Journal"
intext:"Welcome to the Web V.Networks" intitle:"V.Networks [Top]" -filetype:htm
intext:"Welcome to" inurl:"cp" intitle:"H-SPHERE" inurl:"begin.html" -Fee
intext:(password | passcode) intext:(username | userid | user) filetype:csv
intext:construct('mysql:host
intext:gmail invite intext:http://gmail.google.com/gmail/a
intext:SQLiteManager inurl:main.php
intext:ViewCVS inurl:Settings.php
intext:\"Healthy\" + \"Product model\" + \" Client IP\" + \"Ethernet\"
intext:\"index of /\" \"Index of\" access_log
intext:\"SonarQube\" + \"by SonarSource SA.\" + \"LGPL v3\"
intext:\"This is the default welcome page used to test the correct operation of the Apache
intextpassword | passcode) intextusername | userid | user) filetype:csv
intitle:"*- HP WBEM Login" | "You are being prompted to provide login account information for *" | "Please provide the information requested and press
intitle:"--- VIDEO WEB SERVER ---" intext:"Video Web Server" "Any time & Any where" username password
intitle:"500 Internal Server Error" "server at"
intitle:"actiontec" main setup status "Copyright 2001 Actiontec Electronics Inc"
intitle:"Admin Login" "admin login" "blogware"
intitle:"Admin login" "Web Site Administration" "Copyright"
intitle:"admin panel" +"
intitle:"admin panel" +"RedKernel"
intitle:"ADSL Configuration page"
intitle:"Agent web client: Phone Login"
intitle:"AlternC Desktop"
intitle:"Apache Tomcat" "Error Report"
intitle:"Apache::Status" (inurl:server-status | inurl:status.html | inurl:apache.html)
intitle:"AppServ Open Project" -site:www.appservnetwork.com
intitle:"ASP Stats Generator *.*" "ASP Stats Generator" "2003-2004 weppos"
intitle:"Athens Authentication Point"
intitle:"Azureus : Java BitTorrent Client Tracker"
intitle:"b2evo &gt; Login form" "Login form. You must log in! You will have to accept cookies in order to log in" -demo -site:b2evolution.net
intitle:"Belarc Advisor Current Profile" intext:"Click here for Belarc's PC Management products, for large and small companies."
intitle:"Big Sister" +"OK Attention Trouble"
intitle:"BNBT Tracker Info"
intitle:"Browser Launch Page"
intitle:"Cisco CallManager User Options Log On" "Please enter your User ID and Password in the spaces provided below and click the Log On button to co
intitle:"ColdFusion Administrator Login"
intitle:"communigate pro * *" intitle:"entrance"
intitle:"Connection Status" intext:"Current login"
intitle:"Content Management System" "user name"|"password"|"admin" "Microsoft IE 5.5" -mambo
intitle:"curriculum vitae" filetype:doc
intitle:"Default PLESK Page"
intitle:"Dell Remote Access Controller"
intitle:"DocuShare" inurl:"docushare/dsweb/" -faq -gov -edu
intitle:"Docutek ERes - Admin Login" -edu
intitle:"edna:streaming mp3 server" -forums
intitle:"Employee Intranet Login"
intitle:"eMule *" intitle:"- Web Control Panel" intext:"Web Control Panel" "Enter your password here."
intitle:"ePowerSwitch Login"
intitle:"Error Occurred While Processing Request" +WHERE (SELECT|INSERT) filetype:cfm
intitle:"Error Occurred" "The error occurred in" filetype:cfm
intitle:"Error using Hypernews" "Server Software"
intitle:"EverFocus.EDSR.applet"
intitle:"Exchange Log In"
intitle:"Execution of this s?ri?t not permitted"
intitle:"Execution of this script not permitted"
intitle:"eXist Database Administration" -demo
intitle:"EXTRANET * - Identification"
intitle:"EXTRANET login" -.edu -.mil -.gov
intitle:"EZPartner" -netpond
intitle:"Flash Operator Panel" -ext:php -wiki -cms -inurl:asternic -inurl:sip -intitle:ANNOUNCE -inurl:lists
intitle:"FTP root at"
intitle:"Gateway Configuration Menu"
intitle:"Horde :: My Portal" -"[Tickets"
intitle:"Humatrix 8"
intitle:"i-secure v1.1" -edu
intitle:"Icecast Administration Admin Page"
intitle:"iDevAffiliate - admin" -demo
intitle:"inc. vpn 3000 concentrator"
intitle:"index of" "*.cert.pem" | "*.key.pem"
intitle:"index of" "*Maildir/new"
intitle:"Index of" ".htpasswd" "htgroup" -intitle:"dist" -apache -htpasswd.c
intitle:"index of" "/.idea"
intitle:"index of" "/xampp/htdocs" | "C:/xampp/htdocs/"
intitle:"index of" "anaconda-ks.cfg" | "anaconda-ks-new.cfg"
intitle:"index of" "Clientaccesspolicy.xml"
intitle:"index of" "config.exs" | "dev.exs" | "test.exs" | "prod.secret.exs"
intitle:"index of" "credentials.xml" | "credentials.inc" | "credentials.txt"
intitle:"index of" "db.properties" | "db.properties.BAK"
intitle:"index of" "dump.sql"
intitle:"index of" "filezilla.xml"
intitle:"index of" "password.yml
intitle:"index of" "service-Account-Credentials.json" | "creds.json"
intitle:"index of" "sitemanager.xml" | "recentservers.xml"
intitle:"index of" "WebServers.xml"
intitle:"index of" +myd size
intitle:"Index Of" -inurl:maillog maillog size
intitle:"Index of" .bash_history
intitle:"Index of" .mysql_history
intitle:"Index of" .sh_history
intitle:"Index of" cfide
intitle:"Index Of" cookies.txt size
intitle:"index of" etc/shadow
intitle:"index of" htpasswd
intitle:"index of" intext:"apikey.txt
intitle:"index of" intext:"web.xml"
intitle:"index of" intext:connect.inc
intitle:"index of" intext:credentials
intitle:"index of" intext:globals.inc
intitle:"index of" inurl:admin/download
intitle:"index of" master.passwd
intitle:"index of" master.passwd 007 电脑资讯
intitle:"index of" members OR accounts
intitle:"index of" mysql.conf OR mysql_config
intitle:"index of" passwd
intitle:"Index of" passwords modified
intitle:"index of" people.lst
intitle:"index of" pwd.db
intitle:"Index of" pwd.db
intitle:"Index of" sc_serv.conf sc_serv content
intitle:"index of" spwd
intitle:"Index of" spwd.db passwd -pam.conf
intitle:"Index of" upload size parent directory
intitle:"index of" user_carts OR user_cart
intitle:"Index of..etc" passwd
intitle:"index.of *" admin news.asp configview.asp
intitle:"index.of \*" admin news.asp configview.asp
intitle:"index.of" .diz .nfo last modified
intitle:"Insurance Admin Login" | "(c) Copyright 2020 Cityline Websites. All Rights Reserved." | "http://www.citylinewebsites.com"
intitle:"irz" "router" intext:login gsm info -site:*.com -site:*.net
intitle:"ISPMan : Unauthorized Access prohibited"
intitle:"ITS System Information" "Please log on to the SAP System"
intitle:"iVISTA.Main.Page"
intitle:"Joomla - Web Installer"
intitle:"Kurant Corporation StoreSense" filetype:bok
intitle:"ListMail Login" admin -demo
intitle:"live view" intitle:axis
intitle:"Login -
intitle:"Login Forum
intitle:"Login to @Mail" (ext:pl | inurl:"index") -dwaffleman
intitle:"Login to Cacti"
intitle:"Login to the forums - @www.aimoo.com" inurl:login.cfm?id=
intitle:"LOGREP - Log file reporting system" -site:itefix.no
intitle:"Mail Server CMailServer Webmail" "5.2"
intitle:"MailMan Login"
intitle:"Member Login" "NOTE: Your browser must have cookies enabled in order to log into the site." ext:php OR ext:cgi
intitle:"Merak Mail Server Web Administration" -ihackstuff.com
intitle:"microsoft certificate services" inurl:certsrv
intitle:"Microsoft Site Server Analysis"
intitle:"MikroTik RouterOS Managing Webpage"
intitle:"Multimon UPS status page"
intitle:"MvBlog powered"
intitle:"MX Control Console" "If you can't remember"
intitle:"Nessus Scan Report" "This file was generated by Nessus"
intitle:"NetCamSC*"
intitle:"NetCamSC*" | intitle:"NetCamXL*" inurl:index.html
intitle:"NetCamXL*"
intitle:"network administration" inurl:"nic"
intitle:"Novell Web Services" "GroupWise" -inurl:"doc/11924" -.mil -.edu -.gov -filetype:pdf
intitle:"Novell Web Services" intext:"Select a service and a language."
intitle:"OfficeConnect Cable/DSL Gateway" intext:"Checking your browser"
intitle:"oMail-admin Administration - Login" -inurl:omnis.ch
intitle:"OnLine Recruitment Program - Login"
intitle:"Philex 0.2*" -s?ri?t -site:freelists.org
intitle:"Philex 0.2*" -script -site:freelists.org
intitle:"PHP Advanced Transfer" (inurl:index.php | inurl:showrecent.php )
intitle:"PHP Advanced Transfer" inurl:"login.php"
intitle:"php icalendar administration" -site:sourceforge.net
intitle:"PHPBTTracker Statistics" | intitle:"PHPBT Tracker Statistics"
intitle:"phpinfo()" +"mysql.default_password" +"Zend s?ri?ting Language Engine"
intitle:"PhpMyExplorer" inurl:"index.php" -cvs
intitle:"phpPgAdmin - Login" Language
intitle:"PHProjekt - login" login password
intitle:"Please Login" "Use FTM Push"
intitle:"please login" "your password is *"
intitle:"Powered by Pro Chat Rooms"
intitle:"remote assessment" OpenAanval Console
intitle:"Remote Desktop Web Connection"
intitle:"Remote Desktop Web Connection" inurl:tsweb
intitle:"Retina Report" "CONFIDENTIAL INFORMATION"
intitle:"Samba Web Administration Tool" intext:"Help Workgroup"
intitle:"SFXAdmin - sfx_global" | intitle:"SFXAdmin - sfx_local" | intitle:"SFXAdmin - sfx_test"
intitle:"SHOUTcast Administrator" inurl:admin.cgi
intitle:"site administration: please log in" "site designed by emarketsouth"
intitle:"Sphider Admin Login"
intitle:"start.managing.the.device" remote pbx acc
intitle:"statistics of" "advanced web statistics"
intitle:"Supero Doctor III" -inurl:supermicro
intitle:"supervisioncam protocol"
intitle:"SuSE Linux Openexchange Server" "Please activate Javas?ri?t!"
intitle:"SuSE Linux Openexchange Server" "Please activate JavaScript!"
intitle:"switch login" "IBM Fast Ethernet Desktop"
intitle:"SWW link" "Please wait....."
intitle:"sysinfo * " intext:"Generated by Sysinfo * written by The Gamblers."
intitle:"System Statistics" +"System and Network Information Center"
intitle:"teamspeak server-administration
intitle:"Terminal Services Web Connection"
intitle:"Tomcat Server Administration"
intitle:"TOPdesk ApplicationServer"
intitle:"TUTOS Login"
intitle:"TWIG Login"
intitle:"twiki" inurl:"TWikiUsers"
intitle:"Under construction" "does not currently have"
intitle:"Uploader - Uploader v6" -pixloads.com
intitle:"urchin (5|3|admin)" ext:cgi
intitle:"Usage Statistics for" "Generated by Webalizer"
intitle:"vhost" intext:"vHost . 2000-2004"
intitle:"Virtual Server Administration System"
intitle:"VisNetic WebMail" inurl:"/mail/"
intitle:"VitalQIP IP Management System"
intitle:"VMware Management Interface:" inurl:"vmware/en/"
intitle:"VNC viewer for Java"
intitle:"wbem" compaq login "Compaq Information Technologies Group"
intitle:"web client: login"
intitle:"Web Server Statistics for ****"
intitle:"web server status" SSH Telnet
intitle:"web-cyradm"|"by Luc de Louw" "This is only for authorized users" -tar.gz -site:web-cyradm.org
intitle:"WebLogic Server" intitle:"Console Login" inurl:console
intitle:"Welcome Site/User Administrator" "Please select the language" -demos
intitle:"Welcome to F-Secure Policy Manager Server Welcome Page"
intitle:"Welcome to Mailtraq WebMail"
intitle:"welcome to netware *" -site:novell.com
intitle:"Welcome to the Advanced Extranet Server, ADVX!"
intitle:"Welcome to Windows 2000 Internet Services"
intitle:"welcome.to.squeezebox"
intitle:"WJ-NT104 Main Page"
intitle:"WorldClient" intext:"? (2003|2004) Alt-N Technologies."
intitle:"xams 0.0.0..15 - Login"
intitle:"XcAuctionLite" | "DRIVEN BY XCENT" Lite inurl:admin
intitle:"Xenmobile Console Logon"
intitle:"XMail Web Administration Interface" intext:Login intext:password
intitle:"Zope Help System" inurl:HelpSys
intitle:"ZyXEL Prestige Router" "Enter password"
intitle:("Index of" AND "wp-content/plugins/boldgrid-backup/=")
intitle:("TrackerCam Live Video")|("TrackerCam Application Login")|("Trackercam Remote") -trackercam.com
intitle:(“TrackerCam Live Video”)|(“TrackerCam Application Login”)|(“Trackercam Remote”) -trackercam.com
intitle:admin intitle:login
intitle:asterisk.management.portal web-access
intitle:axis intitle:"video server"
intitle:Bookmarks inurl:bookmarks.html "Bookmarks
intitle:Configuration.File inurl:softcart.exe
intitle:dupics inurl:(add.asp | default.asp | view.asp | voting.asp) -site:duware.com
intitle:endymion.sak?.mail.login.page | inurl:sake.servlet
intitle:Group-Office "Enter your username and password to login"
intitle:ilohamail "
intitle:ilohamail intext:"Version 0.8.10" "
intitle:IMP inurl:imp/index.php3
intitle:index of .git/hooks/
intitle:index.of "Apache" "server at"
intitle:index.of administrators.pwd
intitle:index.of cgiirc.config
intitle:index.of cleanup.log
intitle:index.of dead.letter
intitle:Index.of etc shadow
intitle:Index.of etc shadow site:passwd
intitle:index.of inbox
intitle:index.of inbox dbx
intitle:index.of intext:"secring.skr"|"secring.pgp"|"secring.bak"
intitle:index.of master.passwd
intitle:index.of passwd passwd.bak
intitle:index.of people.lst
intitle:index.of trillian.ini
intitle:index.of ws_ftp.ini
intitle:intranet inurl:intranet +intext:"phone"
intitle:liveapplet
intitle:Login * Webmailer
intitle:Login intext:"RT is ? Copyright"
intitle:Login intext:HIKVISION inurl:login.asp?
intitle:Node.List Win32.Version.3.11
intitle:Novell intitle:WebAccess "Copyright *-* Novell, Inc"
intitle:open-xchange inurl:login.pl
intitle:opengroupware.org "resistance is obsolete" "Report Bugs" "Username" "password"
intitle:osCommerce inurl:admin intext:"redistributable under the GNU" intext:"Online Catalog" -demo -site:oscommerce.com
intitle:Ovislink inurl:private/login
intitle:phpMyAdmin "Welcome to phpMyAdmin ***" "running on * as root@*"
intitle:phpnews.login
intitle:plesk inurl:login.php3
intitle:rapidshare intext:login
intitle:Snoop Servlet
intitle:\"index of\" \"debug.log\" OR \"debug-log\"
intitle:\"index of\" \"docker.yml\"
intitle:\"index of\" \"powered by apache \" \"port 80\"
intitle:\"index of\" \"Served by Sun-ONE\"
intitle:\"index of\" \"server at\"
intitle:\"Lists Web Service\"
intitle:\"Microsoft Internet Information Services 8\" -IIS
intitle:\"Monsta ftp\" intext:\"Lock session to IP\"
intitle:\"Web Server's Default Page\" intext:\"hosting using Plesk\" -www
intitle:\"Welcome to JBoss\"
intitle:\"Welcome to nginx!\" intext:\"Welcome to nginx on Debian!\" intext:\"Thank you for\"
inurl:"/admin/configuration. php?" Mystore
inurl:"/axs/ax-admin.pl" -s?ri?t
inurl:"/axs/ax-admin.pl" -script
inurl:"/catalog.nsf" intitle:catalog
inurl:"/cricket/grapher.cgi"
inurl:"/NSearch/AdminServlet"
inurl:"/slxweb.dll/external?name=(custportal|webticketcust)"
inurl:"1220/parse_xml.cgi?"
inurl:"631/admin" (inurl:"op=*") | (intitle:CUPS)
inurl:"8003/Display?what="
inurl:":10000" intext:webmin
inurl:"Activex/default.htm" "Demo"
inurl:"auth_user_file.txt"
inurl:"bookmark.htm"
inurl:"cacti" +inurl:"graph_view.php" +"Settings Tree View" -cvs -RPM
inurl:"calendar.asp?action=login"
inurl:"calendars?ri?t/users.txt"
inurl:"default/login.php" intitle:"kerio"
inurl:"editor/list.asp" | inurl:"database_editor.asp" | inurl:"login.asa" "are set"
inurl:"GRC.DAT" intext:"password"
inurl:"gs/adminlogin.aspx"
inurl:"id=" & intext:"Warning: array_merge()
inurl:"id=" & intext:"Warning: filesize()
inurl:"id=" & intext:"Warning: getimagesize()
inurl:"id=" & intext:"Warning: ilesize()
inurl:"id=" & intext:"Warning: is_writable()
inurl:"id=" & intext:"Warning: mysql_fetch_array()
inurl:"id=" & intext:"Warning: mysql_fetch_assoc()
inurl:"id=" & intext:"Warning: mysql_num_rows()
inurl:"id=" & intext:"Warning: mysql_query()
inurl:"id=" & intext:"Warning: mysql_result()
inurl:"id=" & intext:"Warning: pg_exec()
inurl:"id=" & intext:"Warning: preg_match()
inurl:"id=" & intext:"Warning: require()
inurl:"id=" & intext:"Warning: session_start()
inurl:"id=" & intext:"Warning: Unknown()
inurl:"index.php? module=ew_filemanager"
inurl:"install/install.php"
inurl:"map.asp?" intitle:"WhatsUp Gold"
inurl:"newsletter/admin/"
inurl:"newsletter/admin/" intitle:"newsletter admin"
inurl:"NmConsole/Login.asp" | intitle:"Login - Ipswitch WhatsUp Professional 2005" | intext:"Ipswitch WhatsUp Professional 2005 (SP1)" "Ipswitch, Inc"
inurl:"php121login.php"
inurl:"printer/main.html" intext:"settings"
inurl:"putty.reg"
inurl:"Sites.dat"+"PASS="
inurl:"sitescope.html" intitle:"sitescope" intext:"refresh" -demo
inurl:"slapd.conf" intext:"credentials" -manpage -"Manual Page" -man: -sample
inurl:"slapd.conf" intext:"rootpw" -manpage -"Manual Page" -man: -sample
inurl:"smb.conf" intext:"workgroup" filetype:conf conf
inurl:"suse/login.pl"
inurl:"typo3/index.php?u=" -demo
inurl:"usysinfo?login=true"
inurl:"utilities/TreeView.asp"
inurl:"ViewerFrame?Mode="
inurl:"vsadmin/login" | inurl:"vsadmin/admin" inurl:.php|.asp
inurl:"wvdial.conf" intext:"password"
inurl:"wwwroot/
inurl:*db filetype:mdb
inurl:/*.php?id=
inurl:/adm-cfgedit.php
inurl:/admin/login.asp
inurl:/articles.php?id=
inurl:/calendar.php?token=
inurl:/careers-detail.asp?id=
inurl:/cgi-bin/finger? "In real life"
inurl:/cgi-bin/finger? Enter (account|host|user|username)
inurl:/cgi-bin/pass.txt
inurl:/cgi-bin/sqwebmail?noframes=1
inurl:/Citrix/Nfuse17/
inurl:/CollectionContent.asp?id=
inurl:/commodities.php?*id=
inurl:/config/device/wcd
inurl:/Content.asp?id=
inurl:/counter/index.php intitle:"+PHPCounter 7.*"
inurl:/dana-na/auth/welcome.html
inurl:/db/main.mdb
inurl:/default.php?id=
inurl:/default.php?portalID=
inurl:/Details.asp?id=
inurl:/details.php?linkid=
inurl:/dosearch.asp?
inurl:/eprise/
inurl:/eventdetails.php?*=
inurl:/filedown.php?file=
inurl:/gallery.asp?cid=
inurl:/games.php?id= "Powered by PHPD Game Edition"
inurl:/gmap.php?id=
inurl:/imprimir.php?id=
inurl:/include/footer.inc.php?_AMLconfig[cfg_serverpath]=
inurl:/index.php?pgId=
inurl:/index.php?PID= "Powered By Dew-NewPHPLinks v.2.1b"
inurl:/list_blogs.php?sort_mode=
inurl:/Merchant2/admin.mv | inurl:/Merchant2/admin.mvc | intitle:"Miva Merchant Administration Login" -inurl:cheap-malboro.net
inurl:/modcp/ intext:Moderator+vBulletin
inurl:/mpfn=pdview&id=
inurl:/news.php?include=
inurl:/notizia.php?idArt=
inurl:/os_view_full.php?
inurl:/phpPgAdmin/browser.php
inurl:/prodotti.php?id=
inurl:/publications.asp?type=
inurl:/recipe-view.php?id=
inurl:/reservations.php?id=
inurl:/shared/help.php?page=
inurl:/squirrelcart/cart_content.php?cart_isp_root=
inurl:/SUSAdmin intitle:"Microsoft Software upd?t? Services"
inurl:/SUSAdmin intitle:"Microsoft Software Update Services"
inurl:/view/lang/index.php?page=?page=
inurl:/viewfaqs.php?cat=
inurl:/webedit.* intext:WebEdit Professional -html
inurl:/WhatNew.asp?page=&id=
inurl:/wwwboard
inurl:/xprober ext:php
inurl:/yabb/Members/Admin.dat
inurl:/_layouts/settings
inurl:1810 "Oracle Enterprise Manager"
inurl:2000 intitle:RemotelyAnywhere -site:realvnc.com
inurl::2082/frontend -demo
inurl:?XDEBUG_SESSION_START=phpstorm
inurl:aboutbook.php?id=
inurl:access
inurl:act=
inurl:action=
inurl:admin filetype:db
inurl:admin filetype:xls
inurl:admin intitle:login
inurl:admin inurl:userlist Generic userlist files
inurl:administrator "welcome to mambo"
inurl:ages.php?id=
inurl:ajax.php?page=
inurl:announce.php?id=
inurl:aol*/_do/rss_popup?blogID=
inurl:API_HOME_DIR=
inurl:art.php?idm=
inurl:article.php?ID=
inurl:article.php?id=
inurl:artikelinfo.php?id=
inurl:asp
inurl:avd_start.php?avd=
inurl:axis-cgi/jpg
inurl:axis-cgi/mjpg (motion-JPEG)
inurl:backup filetype:mdb
inurl:band_info.php?id=
inurl:bin.welcome.sh | inurl:bin.welcome.bat | intitle:eHealth.5.0
inurl:board=
inurl:build.err
inurl:buy
inurl:buy.php?category=
inurl:cat=
inurl:category.php?id=
inurl:ccbill filetype:log
inurl:cgi
inurl:cgi-bin inurl:calendar.cfg
inurl:cgi-bin/printenv
inurl:cgi-bin/testcgi.exe "Please distribute TestCGI"
inurl:cgi-bin/ultimatebb.cgi?ubb=login
inurl:cgiirc.config
inurl:changepassword.asp
inurl:channel_id=
inurl:chap-secrets -cvs
inurl:chappies.php?id=
inurl:Citrix/MetaFrame/default/default.aspx
inurl:clanek.php4?id=
inurl:client_id=
inurl:clubpage.php?id=
inurl:cmd=
inurl:collectionitem.php?id=
inurl:communique_detail.php?id=
inurl:config.php dbuname dbpass
inurl:confixx inurl:login|anmeldung
inurl:cont=
inurl:coranto.cgi intitle:Login (Authorized Users Only)
inurl:CrazyWWWBoard.cgi intext:"detailed debugging information"
inurl:csCreatePro.cgi
inurl:current_frame=
inurl:curriculum.php?id=
inurl:data
inurl:date=
inurl:declaration_more.php?decl_id=
inurl:default.asp intitle:"WebCommander"
inurl:detail.php?ID=
inurl:detail=
inurl:dir=
inurl:display=
inurl:download
inurl:download.php?id=
inurl:download=
inurl:downloads_info.php?id=
inurl:ds.py
inurl:email filetype:mdb
inurl:event.php?id=
inurl:exchweb/bin/auth/owalogon.asp
inurl:f=
inurl:faq2.php?id=
inurl:fcgi-bin/echo
inurl:fellows.php?id=
inurl:fiche_spectacle.php?id=
inurl:file
inurl:file=
inurl:fileinclude=
inurl:filename=
inurl:filezilla.xml -cvs
inurl:firm_id=
inurl:footer.inc.php
inurl:forum
inurl:forum filetype:mdb
inurl:forum_bds.php?num=
inurl:forward filetype:forward -cvs
inurl:g=
inurl:galeri_info.php?l=
inurl:gallery.php?id=
inurl:game.php?id=
inurl:games.php?id=
inurl:getdata=
inurl:getmsg.html intitle:hotmail
inurl:gnatsweb.pl
inurl:go=
inurl:historialeer.php?num=
inurl:home
inurl:home.php?pagina=
inurl:hosting_info.php?id=
inurl:hp/device/this.LCDispatcher
inurl:HT=
inurl:html
inurl:htpasswd filetype:htpasswd
inurl:humor.php?id=
inurl:idd=
inurl:ids5web
inurl:iisadmin
inurl:inc
inurl:inc=
inurl:incfile=
inurl:incl=
inurl:include_file=
inurl:include_path=
inurl:index.cgi?aktion=shopview
inurl:index.php?=
inurl:index.php?conteudo=
inurl:index.php?id=
inurl:index.php?load=
inurl:index.php?opcao=
inurl:index.php?principal=
inurl:index.php?show=
inurl:index2.php?option=
inurl:index2.php?to=
inurl:indexFrame.shtml Axis
inurl:infile=
inurl:info
inurl:info.inc.php
inurl:info=
inurl:iniziativa.php?in=
inurl:ir=
inurl:irc filetype:cgi cgi:irc
inurl:item_id=
inurl:kategorie.php4?id=
inurl:labels.php?id=
inurl:lang=
inurl:language=
inurl:lilo.conf filetype:conf password -tatercounter2000 -bootpwd -man
inurl:link=
inurl:list
inurl:load=
inurl:loadpsb.php?id=
inurl:log.nsf -gov
inurl:login filetype:swf swf
inurl:login.asp
inurl:login.cfm
inurl:login.jsp.bak
inurl:login.php "SquirrelMail version"
inurl:look.php?ID=
inurl:mail
inurl:main.php phpMyAdmin
inurl:main.php Welcome to phpMyAdmin
inurl:main.php?id=
inurl:main=
inurl:mainspot=
inurl:ManyServers.htm
inurl:material.php?id=
inurl:memberInfo.php?id=
inurl:metaframexp/default/login.asp | intitle:"Metaframe XP Login"
inurl:mewebmail
inurl:midicart.mdb
inurl:msg=
inurl:names.nsf?opendatabase
inurl:netscape.hst
inurl:netscape.ini
inurl:netw_tcp.shtml
inurl:new
inurl:news-full.php?id=
inurl:news.php?id=
inurl:newscat.php?id=
inurl:newsdesk.cgi? inurl:"t="
inurl:newsDetail.php?id=
inurl:newsid=
inurl:newsitem.php?num=
inurl:newsone.php?id=
inurl:newsticker_info.php?idn=
inurl:news_display.php?getid=
inurl:news_view.php?id=
inurl:nuke filetype:sql
inurl:num=
inurl:ocw_login_username
inurl:odbc.ini ext:ini -cvs
inurl:offer.php?idf=
inurl:ogl_inet.php?ogl_id=
inurl:openfile=
inurl:opinions.php?id=
inurl:orasso.wwsso_app_admin.ls_login
inurl:order
inurl:ospfd.conf intext:password -sample -test -tutorial -download
inurl:ovcgi/jovw
inurl:p=
inurl:page.php?file=
inurl:page.php?id=
inurl:page=
inurl:pageid=
inurl:Pageid=
inurl:pages
inurl:pages.php?id=
inurl:pagina=
inurl:pap-secrets -cvs
inurl:participant.php?id=
inurl:pass.dat
inurl:passlist.txt
inurl:path=
inurl:path_to_calendar=
inurl:perform filetype:ini
inurl:perform.ini filetype:ini
inurl:perl/printenv
inurl:person.php?id=
inurl:pg=
inurl:php.ini filetype:ini
inurl:phpSysInfo/ "created by phpsysinfo"
inurl:play_old.php?id=
inurl:pls/admin_/gateway.htm
inurl:pop.php?id=
inurl:portscan.php "from Port"|"Port Range"
inurl:post.php?id=
inurl:postfixadmin intitle:"postfix admin" ext:php
inurl:preferences.ini "[emule]"
inurl:preview.php?id=
inurl:product-item.php?id=
inurl:product.php?id=
inurl:product.php?mid=
inurl:productdetail.php?id=
inurl:productinfo.php?id=
inurl:Productinfo.php?id=
inurl:product_ranges_view.php?ID=
inurl:produit.php?id=
inurl:prod_detail.php?id=
inurl:prod_info.php?id=
inurl:profiles filetype:mdb
inurl:profile_view.php?id=
inurl:proxy | inurl:wpad ext:pac | ext:dat findproxyforurl
inurl:Proxy.txt
inurl:public
inurl:publications.php?id=
inurl:qry_str=
inurl:ray.php?id=
inurl:read.php?=
inurl:read.php?id=
inurl:readnews.php?id=
inurl:reagir.php?num=
inurl:releases.php?id=
inurl:report "EVEREST Home Edition "
inurl:review.php?id=
inurl:rpSys.html
inurl:rub.php?idr=
inurl:rubp.php?idr=
inurl:rubrika.php?idr=
inurl:ruta=
inurl:safehtml=
inurl:search
inurl:search.php vbulletin
inurl:search/admin.php
inurl:secring ext:skr | ext:pgp | ext:bak
inurl:section.php?id=
inurl:section=
inurl:select_biblio.php?id=
inurl:sem.php3?id=
inurl:server-info "Apache Server Information"
inurl:server-status "apache"
inurl:server.cfg rcon password
inurl:servlet/webacc
inurl:shop
inurl:shop.php?do=part&id=
inurl:shopdbtest.asp
inurl:shopping.php?id=
inurl:shop_category.php?id=
inurl:show.php?id=
inurl:showfile=
inurl:showimg.php?id=
inurl:show_an.php?id=
inurl:shredder-categories.php?id=
inurl:side=
inurl:site_id=
inurl:skin=
inurl:snitz_forums_2000.mdb
inurl:software
inurl:spr.php?id=
inurl:sql.php?id=
inurl:ssl.conf filetype:conf
inurl:staff_id=
inurl:static=
inurl:statrep.nsf -gov
inurl:status.cgi?host=all
inurl:story.php?id=
inurl:str=
inurl:Stray-Questions-View.php?num=
inurl:strona=
inurl:sub=
inurl:support
inurl:sw_comment.php?id=
inurl:tdbin
inurl:tekst.php?idt=
inurl:testcgi xitami
inurl:textpattern/index.php
inurl:theme.php?id=
inurl:title.php?id=
inurl:top10.php?cat=
inurl:tradeCategory.php?id=
inurl:trainers.php?id=
inurl:transcript.php?id=
inurl:tresc=
inurl:url=
inurl:user
inurl:user=
inurl:vbstats.php "page generated"
inurl:ventrilo_srv.ini adminpassword
inurl:view.php?id=
inurl:view/index.shtml
inurl:view/indexFrame.shtml
inurl:view/view.shtml
inurl:viewapp.php?id=
inurl:ViewerFrame?Mode=Refresh
inurl:viewphoto.php?id=
inurl:viewshowdetail.php?id=
inurl:view_ad.php?id=
inurl:view_faq.php?id=
inurl:view_product.php?id=
inurl:vtund.conf intext:pass -cvs
inurl:vtund.conf intext:pass -cvs s
inurl:WCP_USER
inurl:web
inurl:webalizer filetype:png -.gov -.edu -.mil -opendarwin
inurl:webmail./index.pl "Interface"
inurl:website.php?id=
inurl:webutil.pl
inurl:webvpn.html "login" "Please enter your"
inurl:webvpn.html "login" "Please enter your" Login ("admin account info") filetype:log
inurl:wp-mail.php + "There doesn't seem to be any new mail."
inurl:XcCDONTS.asp
inurl:yapboz_detay.asp
inurl:yapboz_detay.asp + View Webcam User Accessing
inurl:zebra.conf intext:password -sample -test -tutorial -download
inurl:\"/phpmyadmin/user_password.php
inurl:\":8088/cluster/apps\"
inurl:\"id=*\" & intext:\"warning mysql_fetch_array()\"
inurl:_vti_bin/Authentication.asmx
invent/details.php?id=
ipsec.conf
ipsec.secrets
irbeautina/product_detail.asp?product_id=
irbeautina/product_detail.php?product_id=
issue.php?id=
item-menu.php?idSubCat=
item.asp?eid=
item.asp?id=
item.asp?iid=
item.asp?itemid=
item.asp?item_id=
item.asp?model=
item.asp?prodtype=
item.asp?shopcd=
item.asp?sub_id=
item.cfm?eid=
item.cfm?itemid=
item.cfm?item_id=
item.cfm?model=
item.cfm?prodtype=
item.cfm?shopcd=
item.php?cat=
item.php?code=
item.php?eid=
item.php?id=
item.php?ID=
item.php?iid=
item.php?item=
item.php?itemid=
item.php?item_id=
item.php?model=
item.php?prodtype=
item.php?shopcd=
item.php?SKU=
item.php?sub_id=
item/detail.php?num=
item/wpa-storefront-the-ultimate-wpecommerce-theme/discussion/61891?page=
itemDesc.asp?CartId=
itemDesc.cfm?CartId=
itemDesc.php?CartId=
itemdetail.asp?item=
itemdetail.cfm?item=
itemdetail.php?item=
itemdetails.asp?catalogid=
itemdetails.cfm?catalogid=
itemdetails.php?catalogid=
itemlist.php?categoryID=
item_book.asp?CAT=
item_book.php?CAT=
item_details.asp?catid=
item_details.cfm?catid=
item_details.php?catid=
item_list.asp?cat_id=
item_list.asp?maingroup
item_list.cfm?maingroup
item_list.php?cat_id=
item_list.php?maingroup
item_show.asp?code_no=
item_show.asp?id=
item_show.asp?lid=
item_show.cfm?code_no=
item_show.php?code_no=
item_show.php?id=
item_show.php?itemID=
item_show.php?lid=
jdbc:mysql://localhost:3306/ + username + password ext:yml | ext:javascript -git -gitlab
jdbc:oracle://localhost: + username + password ext:yml | ext:java -git -gitlab
jdbc:postgresql://localhost: + username + password ext:yml | ext:java -git -gitlab
jdbc:sqlserver://localhost:1433 + username + password ext:yml | ext:java
Jetbox One CMS Ã¢?Â¢" | "
Jetstream ? *")
joblog/index.php?mode=
jobs.php?id=
jobsite_storage_equipment/view_products.php?p_id=
joke-display.php?id=
journal.php?id=
js_product_detail.php?pid=
jump.php?id=
kategorie.php4?id=
kboard/kboard.asp?board=
kboard/kboard.php?board=
kids-detail.php?prodID=
KM/BOARD/readboard.asp?id=
KM/BOARD/readboard.php?id=
knowledgebase/article.php?id=
knowledge_base/detail.asp?id=
knowledge_base/detail.php?id=
kr/product/product.php?gubun=
kshop/home.php?cat=
kshop/product.asp?productid=
kshop/product.php?productid=
lakeinfo.php?id=
latestnews.php?id=
layout.php?abre=
layout.php?action=
layout.php?addr=
layout.php?basepath=
layout.php?c=
layout.php?category=
layout.php?chapter=
layout.php?choix=
layout.php?cmd=
layout.php?cont=
layout.php?disp=
layout.php?g=
layout.php?goto=
layout.php?incl=
layout.php?ir=
layout.php?link=
layout.php?loader=
layout.php?menue=
layout.php?modo=
layout.php?my=
layout.php?nivel=
layout.php?numero=
layout.php?oldal=
layout.php?opcion=
layout.php?OpenPage=
layout.php?page=
layout.php?pageweb=
layout.php?pagina=
layout.php?panel=
layout.php?path=
layout.php?play=
layout.php?pollname=
layout.php?pref=
layout.php?qry=
layout.php?secao=
layout.php?section=
layout.php?seite=
layout.php?sekce=
layout.php?strona=
layout.php?thispage=
layout.php?tipo=
layout.php?url=
layout.php?var=
layout.php?where=
layout.php?xlink=
layout.php?z=
LeapFTP intitle:"index.of./" sites.ini modified
learnmore.asp?cartID=
learnmore.cfm?cartID=
learnmore.php?cartID=
lib/gore.php?libpath=
liblog/index.php?cat=
library.asp?cat=
library.php?author=
library.php?cat=
library/article.php?ID=
Link Department"
link.php?type=
links.asp?catid=
links.cfm?catid=
links.php?cat=
links.php?catid=
Links/browse.php?id=
links/browse.php?id=
links/resources/links_search_result.php?catid=
link_exchange/browse.php?id=
list.asp?bookid=
List.asp?CatID=
list.cfm?bookid=
List.cfm?CatID=
list.php?bookid=
List.php?CatID=
list.php?id=
listcategoriesandproducts.asp?idCategory=
listcategoriesandproducts.cfm?idCategory=
listcategoriesandproducts.php?idCategory=
listing.asp?cat=
listing.php?cat=
list_trust.php?id=
lit_work.php?w_id=
liveapplet
liverpool/details.php?id=
lmsrecords_cd.asp?cdid=
lmsrecords_cd.php?cdid=
loadpsb.php?id=
Login ("
login.php?dir=
Looking Glass
lowell/restaurants.php?id=
ls.asp?id=
ls.php?id=
m/content/article.php?content_id=
m2f/m2f_phpbb204.php?m2f_root_path=
magazin.asp?cid=
magazin.php?cid=
magazine-details.php?magid=
magazines/adult_magazine_full_year.asp?magid=
magazines/adult_magazine_full_year.php?magid=
magazines/adult_magazine_single_page.asp?magid=
magazines/adult_magazine_single_page.php?magid=
magdetail.php?magid=
mail filetype:csv -site:gov intext:name
main.asp?id=
main.asp?item=
main.asp?prodID=
main.php?action=
main.php?addr=
main.php?adresa=
main.php?basepath=
main.php?body=
main.php?category=
main.php?chapter=
main.php?content=
main.php?corpo=
main.php?dir=
main.php?disp=
main.php?doshow=
main.php?e=
main.php?eval=
main.php?filepath=
main.php?goto=
main.php?h=
main.php?id=
main.php?inc=
main.php?include=
main.php?index=
main.php?ir=
main.php?item=
main.php?itemnav=
main.php?j=
main.php?link=
main.php?load=
main.php?loc=
main.php?middle=
main.php?mod=
main.php?my=
main.php?name=
main.php?oldal=
main.php?opcion=
main.php?page=
main.php?pagina=
main.php?param=
main.php?path=
main.php?pg=
main.php?pname=
main.php?pre=
main.php?pref=
main.php?prodID=
main.php?r=
main.php?ref=
main.php?second=
main.php?section=
main.php?site=
main.php?start=
main.php?str=
main.php?strona=
main.php?subject=
main.php?thispage=
main.php?tipo=
main.php?type=
main.php?url=
main.php?v=
main.php?where=
main.php?x=
main.php?xlink=
main/content.php?id=
main/index.asp?action=
main/index.asp?uid=
main/index.php?action=
main/index.php?uid=
main/magpreview.asp?id=
main/magpreview.php?id=
main/product.php?productid=
main/viewItem.php?itemid=
mall/more.asp?ProdID=
mall/more.php?ProdID=
manual.php?product=
master.passwd
materials/item_detail.php?ProductID=
mboard/replies.asp?parent_id=
mboard/replies.php?parent_id=
mb_showtopic.asp?topic_id=
mb_showtopic.php?topic_id=
media.php?****=
media.php?id=
media.php?page=
media/pr.asp?id=
media/pr.php?id=
media_display.php?id=
meetings/presentations.php?id=
melbourne.php?id=
melbourne_details.asp?id=
melbourne_details.php?id=
member-details.php?id=
member.php?ctype=
memberInfo.php?id=
members.php?id=
members/item.php?id=
members/member-profile.php?id=
members/profile.php?id=
memprofile.php?id=
mens/product.php?id=
Merak Mail Server Software" -.gov -.mil -.edu -site:merakmailserver.com
merchandise.php?id=
message/comment_threads.asp?postID=
message/comment_threads.php?postID=
mhp/my***.php?hls=
Microsoft Money Data Files
Midmart Messageboard" "Administrator Login"
mlx/slip_about_sharebacks.php?item=
mod*.php?action=
mod*.php?addr=
mod*.php?b=
mod*.php?channel=
mod*.php?chapter=
mod*.php?choix=
mod*.php?cont=
mod*.php?content=
mod*.php?corpo=
mod*.php?d=
mod*.php?destino=
mod*.php?dir=
mod*.php?ev=
mod*.php?goFile=
mod*.php?home=
mod*.php?incl=
mod*.php?include=
mod*.php?index=
mod*.php?ir=
mod*.php?j=
mod*.php?lang=
mod*.php?link=
mod*.php?m=
mod*.php?middle=
mod*.php?module=
mod*.php?numero=
mod*.php?oldal=
mod*.php?OpenPage=
mod*.php?pag=
mod*.php?pageweb=
mod*.php?pagina=
mod*.php?path=
mod*.php?pg=
mod*.php?phpbb_root_path=
mod*.php?play=
mod*.php?pname=
mod*.php?pre=
mod*.php?qry=
mod*.php?recipe=
mod*.php?secao=
mod*.php?secc=
mod*.php?seccion=
mod*.php?section=
mod*.php?sekce=
mod*.php?start=
mod*.php?strona=
mod*.php?thispage=
mod*.php?tipo=
mod*.php?to=
mod*.php?v=
mod*.php?var=
model.php?item=
modify_en.htm?mode=
modline.asp?id=
modline.cfm?id=
modline.php?id=
modsdetail.php?id=
module/range/dutch_windmill_collection.asp?rangeId=
module/range/dutch_windmill_collection.php?rangeId=
modules.asp?****=
modules.asp?bookid=
modules.php?****=
modules.php?bookid=
modules/AllMyGuests/signin.php?_AMGconfig[cfg_serverpath]=
modules/content/index.asp?id=
modules/content/index.php?id=
modules/coppermine/themes/coppercop/theme.php?THEME_DIR=
modules/forum/index.asp?topic_id=
modules/forum/index.php?topic_id=
modules/My_eGallery/index.php?basepath=
modules/vwar/admin/admin.php?vwar_root=
modules/wfdownloads/singlefile.php?cid=
modules/xfmod/forum/forum.php?thread_id=
module_db.php?pivot_path=
Monster Top List" MTL numrange:200-
more_detail.asp?id=
more_detail.asp?X_EID=
more_detail.php?id=
more_detail.php?X_EID=
More_Details.asp?id=
more_details.asp?id=
More_Details.php?id=
more_details.php?id=
mp-prt.php?item=
mp.php?id=
mpacms/dc/article.php?id=
mt-db-pass.cgi files
mwchat/libs/start_lobby.php?CONFIG[MWCHAT_Libs]=
myaccount.asp?catid=
myaccount.cfm?catid=
myaccount.php?catid=
myevent.php?myevent_path=
mylink.php?id=
myResources_noBanner.php?categoryID=
MYSQL error message: supplied argument....
mysql error with query
mysql history files
MySQL tabledata dumps
mystuff.xml - Trillian data files
m_view.asp?ps_db=
m_view.php?ps_db=
naboard/memo.asp?bd=
naboard/memo.php?bd=
nasar/news.php?id=
natterchat inurl:home.asp -site:natterchat.co.uk
Netscape Application Server Error page
new/showproduct.php?prodid=
news-details.php?id=
news-full.php?id=
news-item.php?id=
news-item.php?newsID=
news-story.php?id=
news.asp?id=
news.asp?ID=
news.asp?t=
news.asp?type=
news.cfm?id=
news.php?articleID=
news.php?category=
news.php?cat_id=
news.php?display=
news.php?id=
news.php?ID=
news.php?item=
news.php?t=
news.php?type=
news/article.php?id=
news/articleRead.php?id=
news/detail.asp?id=
news/detail.php?id=
news/detail.php?ID=
news/details.php?id=
news/index.php?ID=
news/latest_news.asp?cat_id=
news/latest_news.php?cat_id=
news/news-item.php?id=
news/news.asp?id=
news/news.php?id=
news/news/title_show.asp?id=
news/news/title_show.php?id=
news/newsitem.asp?newsID=
news/newsitem.php?newsID=
news/newsitem.php?newsid=
news/newsletter.php?id=
news/news_detail.php?id=
news/press-announcements/press_release.php?press_id=
News/press_release.php?id=
news/press_release.php?id=
news/show.php?id=
news/shownews.php?article=
news/shownewsarticle.asp?articleid=
news/shownewsarticle.php?articleid=
news/temp.asp?id=
news/temp.php?id=
news/v.php?id=
news/viewarticle.php?id=
newsDetail.php?id=
newsDetails.php?ID=
newshop/category.php?c=
newsite/events.php?id=
newsite/pdf_show.asp?id=
newsite/pdf_show.php?id=
newsitem.asp?newsid=
newsitem.asp?newsID=
newsItem.asp?newsId=
newsitem.php?newsid=
newsitem.php?newsID=
newsItem.php?newsId=
newsitem.php?num=
newsletter/newsletter.php?id=
newsletter/newsletter.php?letter=
newsone.php?id=
news_and_notices.asp?news_id=
news_and_notices.php?news_id=
news_content.asp?CategoryID=
news_content.php?CategoryID=
news_detail.asp?id=
news_detail.php?file=
news_detail.php?ID=
news_item.asp?id=
news_item.php?id=
news_more.php?id=
news_view.php?id=
NickServ registration passwords
nightlife/martini.php?cid=
Nina Simone intitle:”index.of” “parent directory” “size” “last modified” “description” I Put A Spell On You (mp4|mp3|avi|flac|aac|ape|ogg) -inurl:(jsp|php|html|aspx|htm|cf|shtml|lyrics-realm|mp3-collection) -site:.info
njm/cntpdf.php?t=
nl/default.asp?id=
nota.php?abre=
nota.php?adresa=
nota.php?b=
nota.php?basepath=
nota.php?base_dir=
nota.php?category=
nota.php?channel=
nota.php?chapter=
nota.php?cmd=
nota.php?content=
nota.php?corpo=
nota.php?destino=
nota.php?disp=
nota.php?doshow=
nota.php?eval=
nota.php?filepath=
nota.php?get=
nota.php?goFile=
nota.php?h=
nota.php?header=
nota.php?home=
nota.php?in=
nota.php?inc=
nota.php?include=
nota.php?ir=
nota.php?itemnav=
nota.php?ki=
nota.php?lang=
nota.php?left=
nota.php?link=
nota.php?m=
nota.php?mid=
nota.php?mod=
nota.php?modo=
nota.php?module=
nota.php?n=
nota.php?nivel=
nota.php?oldal=
nota.php?opcion=
nota.php?OpenPage=
nota.php?option=
nota.php?pag=
nota.php?pagina=
nota.php?panel=
nota.php?pg=
nota.php?play=
nota.php?pollname=
nota.php?pr=
nota.php?pre=
nota.php?qry=
nota.php?rub=
nota.php?sec=
nota.php?secc=
nota.php?seccion=
nota.php?second=
nota.php?seite=
nota.php?sekce=
nota.php?showpage=
nota.php?subject=
nota.php?t=
nota.php?tipo=
nota.php?url=
nota.php?v=
notice/notice_****.php?id=
noticias.php?arq=
notify/notify_form.asp?topic_id=
notify/notify_form.php?topic_id=
Novell NetWare intext:"netware management portal version"
now_viewing.php?id=
nuell/item_show.php?itemID=
nurl:/admin/login.asp
nyheder.htm?show=
n_replyboard.asp?typeboard=
n_replyboard.php?typeboard=
obio/detail.asp?id=
obio/detail.php?id=
obj/print.php?objId=
offer_info.php?id=
ogloszenia/rss.asp?cat=
ogloszenia/rss.php?cat=
ogl_inet.php?ogl_id=
old_reports.php?file=
onlinesales/product.asp?product_id=
onlinesales/product.php?product_id=
onlineshop/productView.php?rangeId=
opinion.php?option=
opinions.php?id=
opportunities/bursary.php?id=
opportunities/event.php?id=
ORA-00921: unexpected end of SQL command
ORA-00936: missing expression
oracle/ifaqmaker.php?id=
order-now.php?prodid=
order.asp?BookID=
order.asp?id=
order.asp?item_ID=
order.asp?lotid=
order.cfm?BookID=
order.cfm?id=
order.cfm?item_ID=
order.php?BookID=
order.php?id=
order.php?item_ID=
order/cart/index.php?maincat_id=
OrderForm.asp?Cart=
OrderForm.cfm?Cart=
OrderForm.php?Cart=
ourblog.asp?categoryid=
ourblog.php?categoryid=
Outlook Web Access (a better way)
ov_tv.asp?item=
ov_tv.php?item=
OWA Public Folders (direct view)
packages_display.asp?ref=
packages_display.php?ref=
package_info.php?id=
padrao.php?*root*=
padrao.php?*[*]*=
padrao.php?a=
padrao.php?abre=
padrao.php?addr=
padrao.php?basepath=
padrao.php?base_dir=
padrao.php?body=
padrao.php?c=
padrao.php?choix=
padrao.php?cont=
padrao.php?corpo=
padrao.php?d=
padrao.php?destino=
padrao.php?eval=
padrao.php?filepath=
padrao.php?h=
padrao.php?header=
padrao.php?incl=
padrao.php?index=
padrao.php?ir=
padrao.php?link=
padrao.php?loc=
padrao.php?menu=
padrao.php?menue=
padrao.php?mid=
padrao.php?middle=
padrao.php?n=
padrao.php?name=
padrao.php?nivel=
padrao.php?oldal=
padrao.php?op=
padrao.php?open=
padrao.php?OpenPage=
padrao.php?pag=
padrao.php?page=
padrao.php?path=
padrao.php?pname=
padrao.php?pre=
padrao.php?qry=
padrao.php?read=
padrao.php?redirect=
padrao.php?rub=
padrao.php?secao=
padrao.php?secc=
padrao.php?seccion=
padrao.php?section=
padrao.php?seite=
padrao.php?sekce=
padrao.php?sivu=
padrao.php?str=
padrao.php?strona=
padrao.php?subject=
padrao.php?texto=
padrao.php?tipo=
padrao.php?type=
padrao.php?u=
padrao.php?url=
padrao.php?var=
padrao.php?xlink=
page.asp?area_id=
page.asp?id=
page.asp?modul=
page.asp?module=
page.asp?PartID=
page.asp?pId=
page.cfm?PartID=
page.php?*[*]*=
page.php?abre=
page.php?action=
page.php?addr=
page.php?adresa=
page.php?area_id=
page.php?base_dir=
page.php?chapter=
page.php?choix=
page.php?cmd=
page.php?cont=
page.php?doc=
page.php?e=
page.php?ev=
page.php?eval=
page.php?file=
page.php?g=
page.php?go=
page.php?goto=
page.php?id=
page.php?inc=
page.php?incl=
page.php?ir=
page.php?left=
page.php?link=
page.php?load=
page.php?loader=
page.php?mid=
page.php?middle=
page.php?mod=
page.php?modo=
page.php?modul=
page.php?module=
page.php?numero=
page.php?oldal=
page.php?OpenPage=
page.php?option=
page.php?p=
page.php?pa=
page.php?panel=
page.php?PartID=
page.php?phpbb_root_path=
page.php?pId=
page.php?pname=
page.php?pref=
page.php?q=
page.php?qry=
page.php?read=
page.php?recipe=
page.php?redirect=
page.php?secao=
page.php?section=
page.php?seite=
page.php?showpage=
page.php?sivu=
page.php?strona=
page.php?subject=
page.php?tipo=
page.php?url=
page.php?where=
page.php?z=
page/de/produkte/produkte.asp?prodID=
page/de/produkte/produkte.php?prodID=
page/venue.asp?id=
page/venue.php?id=
page2.php?id=
pageid=
pages.asp?ID=
pages.asp?id=
pages.php?ID=
pages.php?id=
pages.php?page=
pages/events/specificevent.php?id=
pages/index.php?pID=
pages/print.asp?id=
pages/print.php?id=
pages/product.php?product_id=
pages/video.asp?id=
pages/video.php?id=
Pages/whichArticle.asp?id=
Pages/whichArticle.php?id=
pageType1.php?id=
pageType2.php?id=
page_prod.php?id_cat=
pagina.php?basepath=
pagina.php?base_dir=
pagina.php?category=
pagina.php?channel=
pagina.php?chapter=
pagina.php?choix=
pagina.php?cmd=
pagina.php?dir=
pagina.php?ev=
pagina.php?filepath=
pagina.php?g=
pagina.php?go=
pagina.php?goto=
pagina.php?header=
pagina.php?home=
pagina.php?id=
pagina.php?in=
pagina.php?incl=
pagina.php?include=
pagina.php?index=
pagina.php?ir=
pagina.php?k=
pagina.php?lang=
pagina.php?left=
pagina.php?link=
pagina.php?load=
pagina.php?loader=
pagina.php?loc=
pagina.php?mid=
pagina.php?middlePart=
pagina.php?modo=
pagina.php?my=
pagina.php?n=
pagina.php?nivel=
pagina.php?numero=
pagina.php?oldal=
pagina.php?OpenPage=
pagina.php?pagina=
pagina.php?panel=
pagina.php?path=
pagina.php?pr=
pagina.php?pre=
pagina.php?q=
pagina.php?read=
pagina.php?recipe=
pagina.php?ref=
pagina.php?sec=
pagina.php?secao=
pagina.php?seccion=
pagina.php?section=
pagina.php?sekce=
pagina.php?start=
pagina.php?str=
pagina.php?thispage=
pagina.php?tipo=
pagina.php?to=
pagina.php?type=
pagina.php?u=
pagina.php?v=
pagina.php?z=
painting.php?id=
panditonline/productlist.php?id=
parent directory /appz/ -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory DVDRip -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Gamez -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory MP3 -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Name of Singer or album -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
parent directory Xvid -xxx -html -htm -php -shtml -opendivx -md5 -md5sums
participant.php?id=
passlist
passlist.txt (a better way)
passwd
passwd / etc (reliable)
past-event.asp?id=
past-event.php?id=
path.php?*[*]*=
path.php?action=
path.php?addr=
path.php?adresa=
path.php?body=
path.php?category=
path.php?channel=
path.php?chapter=
path.php?cmd=
path.php?destino=
path.php?disp=
path.php?doshow=
path.php?ev=
path.php?eval=
path.php?filepath=
path.php?goto=
path.php?header=
path.php?home=
path.php?id=
path.php?in=
path.php?incl=
path.php?ir=
path.php?left=
path.php?link=
path.php?load=
path.php?loader=
path.php?menue=
path.php?mid=
path.php?middle=
path.php?middlePart=
path.php?my=
path.php?nivel=
path.php?numero=
path.php?opcion=
path.php?option=
path.php?p=
path.php?pageweb=
path.php?panel=
path.php?path=
path.php?play=
path.php?pname=
path.php?pre=
path.php?pref=
path.php?qry=
path.php?recipe=
path.php?sec=
path.php?secao=
path.php?sivu=
path.php?sp=
path.php?start=
path.php?strona=
path.php?subject=
path.php?thispage=
path.php?tipo=
path.php?type=
path.php?var=
path.php?where=
path.php?xlink=
path.php?y=
payment.asp?CartID=
payment.cfm?CartID=
payment.php?CartID=
PCMA/productDetail.php?prodId=
pdetail.asp?item_id=
pdetail.cfm?item_id=
pdetail.php?item_id=
pdf_post.asp?ID=
pdf_post.php?ID=
people.lst
Peoples MSN contact lists
person.php?id=
pharmaxim/category.asp?cid=
pharmaxim/category.php?cid=
phorum/read.php?3,716,721,quote=
photog.php?id=
photogallery.asp?id=
photogallery.php?id=
PhotoPost PHP Upload
photo_view.php?id=
PHP application warnings failing "include_path"
php-addressbook "This is the addressbook for *" -warning
php/event.php?id=
php/fid27BF3BCB1A648805B511298CE6D643E72B4D59AD.aspx?s=
php/fid8E1BED06B1301BAE3ED64383D5F619E3B1997A70.aspx?s=
php/fid985C124FBD9EF3A29BA8F40521F12D097B0E2016.aspx?s=
php/fidEAD6DDC6CC9D1ADDFD7876B7715A3342E18A865C.aspx?s=
php/index.php?id=
PHPhotoalbum Statistics
PHPhotoalbum Upload
phpOpenTracker" Statistics
phpwcms/include/inc_ext/spaw/dialogs/table.php?spaw_root=
phpx?PageID
picgallery/category.asp?cid=
picgallery/category.php?cid=
pivot/modules/module_db.php?pivot_path=
player.php?id=
play_old.php?id=
Please enter a valid password! inurl:polladmin
podcast/item.asp?pid=
podcast/item.php?pid=
poem.php?id=
poem_list.asp?bookID=
poem_list.php?bookID=
policy.php?id=
ponuky/item_show.asp?ID=
ponuky/item_show.php?ID=
pop.php?id=
port.php?content=
portafolio/portafolio.asp?id=
portafolio/portafolio.php?id=
portfolio.html?categoryid=
post.php?id=
powersearch.asp?CartId=
powersearch.cfm?CartId=
powersearch.php?CartId=
ppads/external.php?type=
preorder.php?bookID=
press.php?*root*=
press.php?*[*]*=
press.php?abre=
press.php?addr=
press.php?base_dir=
press.php?category=
press.php?channel=
press.php?destino=
press.php?dir=
press.php?ev=
press.php?get=
press.php?goFile=
press.php?home=
press.php?i=
press.php?id=
press.php?inc=
press.php?incl=
press.php?include=
press.php?ir=
press.php?itemnav=
press.php?lang=
press.php?link=
press.php?loader=
press.php?menu=
press.php?mid=
press.php?middle=
press.php?modo=
press.php?module=
press.php?my=
press.php?nivel=
press.php?opcion=
press.php?OpenPage=
press.php?option=
press.php?pa=
press.php?page=
press.php?pageweb=
press.php?pagina=
press.php?panel=
press.php?param=
press.php?path=
press.php?pg=
press.php?pname=
press.php?pr=
press.php?pref=
press.php?redirect=
press.php?rub=
press.php?second=
press.php?seite=
press.php?strona=
press.php?subject=
press.php?t=
press.php?thispage=
press.php?to=
press.php?type=
press.php?where=
press.php?xlink=
press/press.php?id=
press2.php?ID=
pressroom/viewnews.php?id=
press_cutting.php?id=
press_release.asp?id=
press_release.php?id=
press_release/release_detail.php?id=
press_releases.php?id=
press_releases/press_releases.php?id=
preview.php?id=
preview.php?pid=
prev_results.asp?prodID=
prev_results.php?prodID=
price.asp
price.cfm
price.php
principal.php?abre=
principal.php?addr=
principal.php?b=
principal.php?basepath=
principal.php?choix=
principal.php?cont=
principal.php?conteudo=
principal.php?corpo=
principal.php?d=
principal.php?destino=
principal.php?disp=
principal.php?ev=
principal.php?eval=
principal.php?f=
principal.php?filepath=
principal.php?goto=
principal.php?header=
principal.php?home=
principal.php?id=
principal.php?in=
principal.php?inc=
principal.php?index=
principal.php?ir=
principal.php?ki=
principal.php?l=
principal.php?left=
principal.php?link=
principal.php?load=
principal.php?loader=
principal.php?loc=
principal.php?menue=
principal.php?middle=
principal.php?middlePart=
principal.php?module=
principal.php?my=
principal.php?n=
principal.php?nivel=
principal.php?oldal=
principal.php?opcion=
principal.php?p=
principal.php?pag=
principal.php?pagina=
principal.php?param=
principal.php?phpbb_root_path=
principal.php?pollname=
principal.php?pr=
principal.php?pre=
principal.php?pref=
principal.php?q=
principal.php?read=
principal.php?recipe=
principal.php?ref=
principal.php?rub=
principal.php?s=
principal.php?secc=
principal.php?seccion=
principal.php?seite=
principal.php?strona=
principal.php?subject=
principal.php?tipo=
principal.php?to=
principal.php?type=
principal.php?url=
principal.php?viewpage=
principal.php?w=
principal.php?z=
print-story.asp?id=
print-story.php?id=
print.asp?id=
print.asp?ID=
print.asp?sid=
print.php?*root*=
print.php?addr=
print.php?basepath=
print.php?base_dir=
print.php?category=
print.php?chapter=
print.php?choix=
print.php?cont=
print.php?dir=
print.php?disp=
print.php?doshow=
print.php?g=
print.php?goFile=
print.php?goto=
print.php?header=
print.php?id=
print.php?ID=
print.php?in=
print.php?inc=
print.php?itemnav=
print.php?ki=
print.php?l=
print.php?left=
print.php?link=
print.php?loc=
print.php?menu=
print.php?menue=
print.php?middle=
print.php?middlePart=
print.php?module=
print.php?my=
print.php?name=
print.php?numero=
print.php?opcion=
print.php?open=
print.php?OpenPage=
print.php?option=
print.php?pag=
print.php?page=
print.php?param=
print.php?path=
print.php?play=
print.php?pname=
print.php?pollname=
print.php?pre=
print.php?r=
print.php?read=
print.php?rub=
print.php?s=
print.php?sekce=
print.php?sid=
print.php?sivu=
print.php?sp=
print.php?str=
print.php?strona=
print.php?thispage=
print.php?tipo=
print.php?type=
print.php?u=
print.php?where=
printarticle.php?id=
printcards.asp?ID=
printcards.php?ID=
privacy.asp?cartID=
privacy.cfm?cartID=
privacy.php?cartID=
private key files (.csr)
private key files (.key)
prod.asp?cat=
prod.php?cat=
prod.php?Cat=
prodbycat.asp?intCatalogID=
prodbycat.cfm?intCatalogID=
prodbycat.php?intCatalogID=
proddetail.php?prod=
proddetails_print.php?prodid=
prodetails.asp?prodid=
prodetails.cfm?prodid=
prodetails.php?prodid=
prodlist.asp?catid=
prodlist.cfm?catid=
prodlist.php?catid=
prodotti.asp?id_cat=
prodotti.php?id_cat=
prodrev.php?cat=
product-detail.php?prodid=
product-details.php?prodID=
product-details.php?prodId=
product-info.php?cat=
product-item.php?id=
product-list.asp?category_id=
product-list.asp?cid=
product-list.asp?id=
product-list.php?category_id=
product-list.php?cid=
product-list.php?id=
product-list.php?ID=
product-range.asp?rangeID=
product-range.php?rangeID=
product.asp?****=
product.asp?bid=
product.asp?bookID=
product.asp?cat=
product.asp?id=
product.asp?id_h=
product.asp?intProdID=
product.asp?intProductID=
product.asp?ItemID=
product.asp?pid=
product.asp?prd=
product.asp?prodid=
product.asp?product=
product.asp?ProductID=
product.asp?productid=
product.asp?product_id=
product.asp?shopprodid=
product.asp?sku=
product.cfm?bookID=
product.cfm?intProdID=
product.php?****=
product.php?bid=
product.php?bookID=
product.php?brand=
product.php?c=
product.php?cat=
product.php?cat_id=
product.php?fdProductId=
product.php?id=
product.php?id_h=
product.php?inid=
product.php?intProdID=
product.php?intProductID=
product.php?ItemID=
product.php?ItemId=
product.php?lang=
product.php?par=
product.php?pcid=
product.php?pid=
product.php?pl=
product.php?prd=
product.php?prodid=
product.php?product=
product.php?ProductID=
product.php?productid=
product.php?products_id=
product.php?product_id=
product.php?product_no=
product.php?prod_num=
product.php?proid=
product.php?proID=
product.php?rangeid=
product.php?shopprodid=
Product.php?Showproduct=
product.php?sku=
product.search.php?proid=
product/detail.asp?id=
product/detail.php?id=
product/list.asp?pid=
product/list.php?pid=
product/product.asp?cate=
product/product.asp?product_no=
product/product.php?cate=
product/product.php?product_no=
product2.php?id=
product3.php?id=
productdetail.php?id=
productDetail.php?prodId=
productDetail.php?prodID=
productDetails.asp?idProduct=
productDetails.cfm?idProduct=
productDetails.php?id=
ProductDetails.php?id=
productDetails.php?idProduct=
productdetails.php?prodId=
productDetails.php?prodId=
ProductDetails.php?ProdID=
productdetails.php?prodid=
productDisplay.asp
productDisplay.cfm
productDisplay.php
productinfo.asp?item=
productinfo.cfm?item=
productinfo.php?id=
productinfo.php?item=
productList.asp?cat=
productlist.asp?fid=
productlist.asp?grpid=
productlist.asp?id=
ProductList.asp?id=
productList.asp?id=
productlist.asp?tid=
productlist.asp?ViewType=Category&CategoryID=
productlist.cfm?ViewType=Category&CategoryID=
productList.php?cat=
productlist.php?cat=
productlist.php?fid=
productlist.php?grpid=
productlist.php?id=
ProductList.php?id=
productList.php?id=
productlist.php?tid=
productlist.php?ViewType=Category&CategoryID=
productpage.asp
productpage.cfm
productpage.php
productpage.php?ID=
products-display-details.asp?prodid=
products-display-details.php?prodid=
products.asp?act=
products.asp?cat=
products.asp?categoryID=
products.asp?catid=
products.asp?cat_id=
products.asp?DepartmentID=
products.asp?groupid=
products.asp?ID=
products.asp?keyword=
products.asp?openparent=
products.asp?p=
products.asp?rub=
products.asp?type=
products.cfm?ID=
products.cfm?keyword=
products.html?file=
products.php?act=
products.php?area_id=
products.php?cat=
products.php?categoryID=
products.php?catid=
products.php?catId=
products.php?cat_id=
products.php?cid=
products.php?DepartmentID=
products.php?groupid=
products.php?ID=
products.php?id=
products.php?keyword=
products.php?mainID=
products.php?openparent=
products.php?p=
products.php?page=
products.php?parent=
products.php?req=
products.php?rub=
products.php?session=
products.php?sku=
products.php?sub=
products.php?subgroupid=
products.php?type=
products/?catID=
products/Blitzball.htm?id=
products/card.asp?prodID=
products/card.php?prodID=
products/category.php?id=
Products/Catsub.php?recordID=
products/display_product.php?product_id=
products/index.asp?rangeid=
products/index.php?cat=
products/index.php?rangeid=
products/item_show.php?itemId=
Products/mfr.php?mfg=
products/model.php?id=
products/parts/detail.asp?id=
products/parts/detail.php?id=
products/product-list.asp?id=
products/product-list.php?id=
products/product.asp?ID=
products/product.asp?id=
products/product.asp?pid=
products/product.php?article=
products/product.php?id=
products/product.php?pid=
Products/product.php?pid=
products/productdetails.php?prodID=
products/products.asp?p=
products/products.php?cat=
products/products.php?p=
Products/products.php?showonly=
products/testimony.php?id=
products/treedirectory.asp?id=
productsByCategory.asp?intCatalogID=
productsByCategory.cfm?intCatalogID=
productsByCategory.php?intCatalogID=
productsview.asp?proid=
productsview.php?proid=
products_category.asp?CategoryID=
products_category.cfm?CategoryID=
products_category.php?CategoryID=
products_connections_detail.php?cat_id=
products_detail.asp?CategoryID=
products_detail.cfm?CategoryID=
products_detail.php?CategoryID=
products_detail.php?id=
productview.php?id=
product_customed.php?pid=
product_detail.asp?product_id=
product_detail.cfm?id=
product_detail.php?id=
product_detail.php?prodid=
product_detail.php?product_id=
product_details.asp?id=
product_details.asp?prodid=
product_details.asp?product_id=
product_details.php?id=
product_details.php?prodid=
product_details.php?prodID=
product_details.php?product_id=
product_guide/company_detail.php?id=
product_info.asp?id=
product_info.asp?item_id=
product_info.asp?products_id=
product_info.cfm?item_id=
product_info.php?id=
product_info.php?item_id=
product_info.php?products_id=
product_page.php?id=
product_ranges_view.asp?ID=
product_ranges_view.php?ID=
product_reviews.php?feature_id=
produit.php?id=
prodView.asp?idProduct=
prodView.cfm?idProduct=
prodView.php?idProduct=
prod_detail.php?id=
prod_details.php?id=
prod_details.php?products_id=
prod_indiv.php?groupid=
prod_info.php?id=
prod_show.asp?id=
prod_show.asp?prodid=
profile.asp?id=
profile.php?id=
profile.php?objID=
profile/detail.php?id=
profile/newsdetail.php?id=
profiles/profile.asp?profileid=
profiles/profile.php?profileid=
profile_print.asp?id=
profile_print.php?id=
profile_view.php?id=
program/details.php?ID=
projDetail.php?id=
projdetail.php?id=
projdetails.asp?id=
projdetails.php?id=
projectdisplay.php?pid=
projects/detail.php?id=
projects/event.asp?id=
projects/event.php?id=
projects/project.php?id=
projects/pview.php?id=
projects/view.php?id=
promo.asp?id=
promo.cfm?id=
promo.php?id=
promotion.asp?catid=
promotion.cfm?catid=
promotion.php?catid=
promotion.php?id=
properties.asp?id_cat=
properties.php?id_cat=
property.asp?id=
property.php?id=
psyBNC config files
psychology/people/detail.asp?id=
psychology/people/detail.php?id=
pub/pds/pds_view.asp?start=
pub/pds/pds_view.php?start=
publication/ontarget_details.php?oid=
publications.asp?Id=
publications.asp?id=
publications.asp?ID=
publications.php?Id=
publications.php?id=
publications.php?ID=
publications/?id=
publications/book_reviews/full_review.asp?id=
publications/book_reviews/full_review.php?id=
publications/publication.asp?id=
publications/publication.php?id=
publications/view.asp?id=
publications/view.php?id=
public_individual_sponsorship.php?ID=
pubs-details.php?id=
pubs_more2.php?id=
purelydiamond/products/category.asp?cat=
purelydiamond/products/category.php?cat=
pview.asp?Item=
pview.cfm?Item=
pview.php?Item=
pwd.db
pylones/item.php?item=
queries/lostquotes/?id=
questions.asp?questionid=
questions.php?questionid=
Quicken data files
Range.php?rangeID=
rating.asp?id=
rating.php?id=
rating/stat.asp?id=
rating/stat.php?id=
ray.php?id=
rca/store/item.php?item=
rdbqds -site:.edu -site:.mil -site:.gov
read.php?id=
read.php?in=
readnews.php?id=
reagir.php?num=
recipe/category.asp?cid=
recipe/category.php?cid=
record_profile.php?id=
redaktion/whiteteeth/detail.asp?nr=
redaktion/whiteteeth/detail.php?nr=
RedKernel"
referral/detail.asp?siteid=
referral/detail.php?siteid=
release.php?id=
releases.php?id=
releases_headlines_details.asp?id=
releases_headlines_details.php?id=
remixer.php?id=
rentals.php?id=
reply.asp?id=
reply.php?id=
report-detail.asp?id=
resellers.asp?idCategory=
resellers.cfm?idCategory=
resellers.php?idCategory=
resource.php?id=
resources/category.php?CatID=
resources/detail.asp?id=
resources/detail.php?id=
resources/index.asp?cat=
resources/index.php?cat=
resources/vulnerabilities_list.asp?id=
resources/vulnerabilities_list.php?id=
ressource.php?ID=
restaurant.php?id=
results.asp?cat=
results.cfm?cat=
results.php?cat=
retail/index_bobby.php?id=
review.php?id=
review/review_form.asp?item_id=
review/review_form.php?item_id=
reviews.asp?id=
reviews.php?id=
reviews/index.php?cat=
reviews/more_details.php?id=
rmcs/opencomic.phtml?rowid=
robots.txt
rounds-detail.asp?id=
rounds-detail.php?id=
rss.asp?cat=
rss.php?cat=
rss.php?id=
rss/event.asp?id=
rss/event.php?id=
rtfe.asp?siteid=
rtfe.php?siteid=
rub.php?idr=
rural/rss.php?cat=
s.asp?w=
s.php?w=
Sales/view_item.asp?id=
Sales/view_item.php?id=
savecart.asp?CartId=
savecart.cfm?CartId=
savecart.php?CartId=
schule/termine.asp?view=
schule/termine.php?view=
scripts/comments.php?id=
search***.php?ki=
search.asp?CartID=
search.cfm?CartID=
search.php?CartID=
search.php?cutepath=
search.php?q=
search/display.asp?BookID=
search/display.php?BookID=
search/index.php?q=
searchcat.asp?search_id=
searchcat.cfm?search_id=
searchcat.php?search_id=
SearchProduct/ListProduct.php?PClassify_3_SN=
Search_Data_Sheet.asp?ID=
secondary.php?id=
section.asp?section=
section.php?id=
section.php?parent=
section.php?section=
sectionpage.php?id=
select_biblio.php?id=
Select_Item.asp?id=
Select_Item.cfm?id=
Select_Item.php?id=
sem.php3?id=
send_reminders.php?includedir=
server-dbs "intitle:index of"
Server: Mida eFramework
Services.asp?ID=
Services.cfm?ID=
Services.php?ID=
services.php?page=
services_details_description.php?id=
seWork.aspx?WORKID=
shareit/readreviews.php?cat=
shippinginfo.asp?CartId=
shippinginfo.cfm?CartId=
shippinginfo.php?CartId=
shop.asp?a=
shop.asp?action=
shop.asp?bookid=
shop.asp?cartID=
shop.asp?id=
shop.cfm?a=
shop.cfm?action=
shop.cfm?bookid=
shop.cfm?cartID=
shop.php?a=
shop.php?action=
shop.php?bookid=
shop.php?cartID=
shop.php?do=part&id=
shop.php?id_cat=
shop/books_detail.asp?bookID=
shop/books_detail.php?bookID=
shop/category.asp?cat_id=
shop/category.php?cat_id=
shop/eventshop/product_detail.asp?itemid=
shop/eventshop/product_detail.php?itemid=
Shop/home.asp?cat=
Shop/home.php?cat=
shop/home.php?cat=
shop/index.asp?cPath=
shop/index.php?cat_id=
shop/index.php?cPath=
shop/pages.php?page=
shop/product.php?id=
shop/products.php?cat=
shop/products.php?cat_id=
shop/products.php?p=
shop/product_details.php?ProdID=
shop/shop.php?id=
shopaddtocart.asp
shopaddtocart.asp?catalogid=
shopaddtocart.cfm
shopaddtocart.cfm?catalogid=
shopaddtocart.php
shopaddtocart.php?catalogid=
shopbasket.asp?bookid=
shopbasket.cfm?bookid=
shopbasket.php?bookid=
shopbycategory.asp?catid=
shopbycategory.cfm?catid=
shopbycategory.php?catid=
shopcafe-shop-product.asp?bookId=
shopcafe-shop-product.php?bookId=
shopcart.asp?title=
shopcart.cfm?title=
shopcart.php?title=
shopcreatorder.asp
shopcreatorder.cfm
shopcreatorder.php
shopcurrency.asp?cid=
shopcurrency.cfm?cid=
shopcurrency.php?cid=
shopdc.asp?bookid=
shopdc.cfm?bookid=
shopdc.php?bookid=
shopdisplaycategories.asp
shopdisplaycategories.cfm
shopdisplaycategories.php
shopdisplayproduct.asp?catalogid=
shopdisplayproduct.cfm?catalogid=
shopdisplayproduct.php?catalogid=
shopdisplayproducts.asp
shopdisplayproducts.cfm
shopdisplayproducts.php
shopexd.asp
shopexd.asp?catalogid=
shopexd.cfm
shopexd.cfm?catalogid=
shopexd.php
shopexd.php?catalogid=
shopping.php?id=
shopping/index.php?id=
shopping_article.php?id=
shopping_basket.asp?cartID=
shopping_basket.cfm?cartID=
shopping_basket.php?cartID=
shopprojectlogin.asp
shopprojectlogin.cfm
shopprojectlogin.php
shopquery.asp?catalogid=
shopquery.cfm?catalogid=
shopquery.php?catalogid=
shopremoveitem.asp?cartid=
shopremoveitem.cfm?cartid=
shopremoveitem.php?cartid=
shopreviewadd.asp?id=
shopreviewadd.cfm?id=
shopreviewadd.php?id=
shopreviewlist.asp?id=
shopreviewlist.cfm?id=
shopreviewlist.php?id=
ShopSearch.asp?CategoryID=
ShopSearch.cfm?CategoryID=
ShopSearch.php?CategoryID=
shoptellafriend.asp?id=
shoptellafriend.cfm?id=
shoptellafriend.php?id=
shopthanks.asp
shopthanks.cfm
shopthanks.php
shopwelcome.asp?title=
shopwelcome.cfm?title=
shopwelcome.php?title=
shop_category.php?id=
shop_details.asp?prodid=
shop_details.cfm?prodid=
shop_details.php?prodid=
shop_display_products.asp?cat_id=
shop_display_products.php?cat_id=
show-book.asp?id=
show-book.php?id=
show.asp?id=
show.php?*root*=
show.php?abre=
show.php?adresa=
show.php?b=
show.php?base_dir=
show.php?channel=
show.php?chapter=
show.php?cmd=
show.php?corpo=
show.php?d=
show.php?disp=
show.php?filepath=
show.php?get=
show.php?go=
show.php?header=
show.php?home=
show.php?id=
show.php?inc=
show.php?incl=
show.php?include=
show.php?index=
show.php?ir=
show.php?item=
show.php?j=
show.php?ki=
show.php?l=
show.php?left=
show.php?loader=
show.php?m=
show.php?mid=
show.php?middlePart=
show.php?modo=
show.php?module=
show.php?my=
show.php?n=
show.php?nivel=
show.php?oldal=
show.php?page=
show.php?pageweb=
show.php?pagina=
show.php?param=
show.php?path=
show.php?play=
show.php?pname=
show.php?pre=
show.php?qry=
show.php?r=
show.php?read=
show.php?recipe=
show.php?redirect=
show.php?seccion=
show.php?second=
show.php?sp=
show.php?thispage=
show.php?to=
show.php?type=
show.php?x=
show.php?xlink=
show.php?z=
showbook.asp?bookid=
showbook.cfm?bookid=
showbook.php?bookid=
showfeature.asp?id=
showfeature.php?id=
showimg.php?id=
showmedia.php?id=
showPage.php?type=
showproduct.asp?cat=
showproduct.asp?prodid=
showproduct.asp?productId=
showproduct.php?cat=
showproduct.php?prodid=
showproduct.php?productId=
showproducts.php?cid=
showStore.asp?catID=
showStore.cfm?catID=
showStore.php?catID=
showsub.asp?id=
showsub.php?id=
showthread.php?p=
showthread.php?t=
showthread.php?tid=
show_an.php?id=
show_bug.cgi?id=
show_cv.php?id=
show_item.asp?id=
show_item.cfm?id=
show_item.php?id=
show_item_details.asp?item_id=
show_item_details.cfm?item_id=
show_item_details.php?item_id=
show_news.php?cutepath=
show_news.php?id=
show_prod.php?p=
show_upload.php?id=
shprodde.asp?SKU=
shprodde.cfm?SKU=
shprodde.php?SKU=
shredder-categories.php?id=
signed-details.php?id=
signin filetype:url
sinformer/n/imprimer.asp?id=
sinformer/n/imprimer.php?id=
singer/detail.asp?siteid=
singer/detail.php?siteid=
site.asp?id=
site.php?id=
site/?details&prodid=
site/cat.php?setlang=
site/catalog.php?cid=
site/catalog.php?pid=
site/en/list_service.asp?cat=
site/en/list_service.php?cat=
site/marketing_article.php?id=
site/products.asp?prodid=
site/products.php?prodid=
site/public/newsitem.php?newsID=
site/view8b.php?id=
site:*gov.* intitle:index.of db
site:.pk intext:Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource in & “id”
site:.pk intext:Warning: mysql_free_result(): supplied argument is not a valid MySQL result resource in & “id”
site:checkin.*.* intitle:"login"
site:edu admin grades
site:ftp.*.*.* "ComputerName=" + "[Unattended] UnattendMode"
site:ftp.*.com \"Web File Manager\"
site:gov ext:sql | ext:dbf | ext:mdb
site:netcraft.com intitle:That.Site.Running Apache
site:password.*.* intitle:"login"
site:portal.*.* intitle:"login"
site:sftp.*.*/ intext:"login" intitle:"server login"
site:user.*.* intitle:"login"
site:www.mailinator.com inurl:ShowMail.do
sitebuildercontent
sitebuilderfiles
sitebuilderpictures
site_list.php?sort=
sitio.php?*root*=
sitio.php?abre=
sitio.php?addr=
sitio.php?body=
sitio.php?category=
sitio.php?chapter=
sitio.php?content=
sitio.php?destino=
sitio.php?disp=
sitio.php?doshow=
sitio.php?e=
sitio.php?ev=
sitio.php?get=
sitio.php?go=
sitio.php?goFile=
sitio.php?inc=
sitio.php?incl=
sitio.php?index=
sitio.php?ir=
sitio.php?left=
sitio.php?menu=
sitio.php?menue=
sitio.php?mid=
sitio.php?middlePart=
sitio.php?modo=
sitio.php?name=
sitio.php?nivel=
sitio.php?oldal=
sitio.php?opcion=
sitio.php?option=
sitio.php?pageweb=
sitio.php?param=
sitio.php?pg=
sitio.php?pr=
sitio.php?qry=
sitio.php?r=
sitio.php?read=
sitio.php?recipe=
sitio.php?redirect=
sitio.php?rub=
sitio.php?sec=
sitio.php?secao=
sitio.php?secc=
sitio.php?section=
sitio.php?sivu=
sitio.php?sp=
sitio.php?start=
sitio.php?strona=
sitio.php?t=
sitio.php?texto=
sitio.php?tipo=
sitio/item.asp?idcd=
sitio/item.php?idcd=
skins/advanced/advanced1.php?pluginpath[0]=
skunkworks/content.asp?id=
skunkworks/content.php?id=
smarty_config.php?root_dir=
Snitz! forums db path error
socsci/events/full_details.asp?id=
socsci/events/full_details.php?id=
socsci/news_items/full_story.asp?id=
socsci/news_items/full_story.php?id=
soe_sign_action.php?id=
software_categories.asp?cat_id=
software_categories.php?cat_id=
solpot.html?body=
solutions/item.php?id=
song.php?ID=
sources/join.php?FORM[url]=owned&CONFIG[captcha]=1&CONFIG[path]=
specials.asp?id=
specials.asp?osCsid=
specials.cfm?id=
specials.php?id=
specials.php?osCsid=
specials/nationvdo/showvdo.php?cateid=
specials/Specials_Pick.php?id=
special_offers/more_details.php?id=
speed-dating/booking.php?id=
sport.asp?revista=
sport.php?revista=
sport/sport.php?id=
spr.php?id=
spwd.db / passwd
SQL data dumps
SQL syntax error
sql.php?id=
SQuery/lib/gore.php?libpath=
Squid cache server reports
ss.php?id=
ssh_host_dsa_key.pub + ssh_host_key + ssh_config = "index of / "
ßæÏ:
Stacks/storyprof.php?ID=
staff/publications.asp?sn=
staff/publications.php?sn=
stafflist/profile.php?id=
staff_id=
standard.php?*[*]*=
standard.php?abre=
standard.php?action=
standard.php?base_dir=
standard.php?body=
standard.php?channel=
standard.php?chapter=
standard.php?cmd=
standard.php?cont=
standard.php?destino=
standard.php?dir=
standard.php?e=
standard.php?ev=
standard.php?eval=
standard.php?go=
standard.php?goFile=
standard.php?goto=
standard.php?home=
standard.php?in=
standard.php?include=
standard.php?index=
standard.php?j=
standard.php?lang=
standard.php?link=
standard.php?menu=
standard.php?middle=
standard.php?my=
standard.php?name=
standard.php?numero=
standard.php?oldal=
standard.php?op=
standard.php?open=
standard.php?pagina=
standard.php?panel=
standard.php?param=
standard.php?phpbb_root_path=
standard.php?pollname=
standard.php?pr=
standard.php?pre=
standard.php?pref=
standard.php?q=
standard.php?qry=
standard.php?ref=
standard.php?s=
standard.php?secc=
standard.php?seccion=
standard.php?section=
standard.php?showpage=
standard.php?sivu=
standard.php?str=
standard.php?subject=
standard.php?url=
standard.php?var=
standard.php?viewpage=
standard.php?w=
standard.php?where=
standard.php?xlink=
standard.php?z=
start.php?*root*=
start.php?abre=
start.php?addr=
start.php?adresa=
start.php?b=
start.php?basepath=
start.php?base_dir=
start.php?body=
start.php?chapter=
start.php?cmd=
start.php?corpo=
start.php?destino=
start.php?eval=
start.php?go=
start.php?header=
start.php?home=
start.php?in=
start.php?include=
start.php?index=
start.php?ir=
start.php?lang=
start.php?load=
start.php?loader=
start.php?mid=
start.php?modo=
start.php?module=
start.php?name=
start.php?nivel=
start.php?o=
start.php?oldal=
start.php?op=
start.php?option=
start.php?p=
start.php?pageweb=
start.php?panel=
start.php?param=
start.php?pg=
start.php?play=
start.php?pname=
start.php?pollname=
start.php?rub=
start.php?secao=
start.php?seccion=
start.php?seite=
start.php?showpage=
start.php?sivu=
start.php?sp=
start.php?str=
start.php?strona=
start.php?thispage=
start.php?tipo=
start.php?where=
start.php?xlink=
stat.asp?id=
stat.php?id=
static.asp?id=
static.php?id=
stdetail.php?prodID=
Steamboat_Springs_Vacation_Rental.php?ID=
stockists_list.asp?area_id=
stockists_list.php?area_id=
store-detail.php?ID=
store-details.asp?id=
store-details.cfm?id=
store-details.php?id=
store.asp?cat_id=
store.asp?id=
store.cfm?id=
store.php?cat_id=
store.php?id=
store/customer/product.php?productid=
store/default.asp?cPath=
store/default.php?cPath=
store/description.asp?iddesc=
store/description.php?iddesc=
store/detail.php?prodid=
store/home.asp?cat=
store/home.php?cat=
store/index.asp?cat_id=
store/index.php?cat_id=
store/item.php?id=
store/mcart.php?ID=
store/news_story.php?id=
store/product.asp?productid=
store/product.php?productid=
store/products.php?cat_id=
store/showcat.php?cat_id=
store/store.php?cat_id=
store/store_detail.php?id=
store/view_items.asp?id=
store/view_items.php?id=
storefront.asp?id=
storefront.cfm?id=
storefront.php?id=
storefronts.asp?title=
storefronts.cfm?title=
storefronts.php?title=
storeitem.asp?item=
storeitem.cfm?item=
storeitem.php?item=
storemanager/contents/item.asp?page_code=
storemanager/contents/item.php?page_code=
StoreRedirect.asp?ID=
StoreRedirect.cfm?ID=
StoreRedirect.php?ID=
store_bycat.asp?id=
store_bycat.cfm?id=
store_bycat.php?id=
store_listing.asp?id=
store_listing.cfm?id=
store_listing.php?id=
store_prod_details.php?ProdID=
Store_ViewProducts.asp?Cat=
Store_ViewProducts.cfm?Cat=
Store_ViewProducts.php?Cat=
story.asp?id=
story.php?id=
Stray-Questions-View.php?num=
sub*.php?*root*=
sub*.php?*[*]*=
sub*.php?abre=
sub*.php?action=
sub*.php?adresa=
sub*.php?b=
sub*.php?basepath=
sub*.php?base_dir=
sub*.php?body=
sub*.php?category=
sub*.php?channel=
sub*.php?chapter=
sub*.php?cont=
sub*.php?content=
sub*.php?corpo=
sub*.php?destino=
sub*.php?g=
sub*.php?go=
sub*.php?goFile=
sub*.php?header=
sub*.php?id=
sub*.php?include=
sub*.php?ir=
sub*.php?itemnav=
sub*.php?j=
sub*.php?k=
sub*.php?lang=
sub*.php?left=
sub*.php?link=
sub*.php?load=
sub*.php?menue=
sub*.php?mid=
sub*.php?middle=
sub*.php?mod=
sub*.php?modo=
sub*.php?module=
sub*.php?my=
sub*.php?name=
sub*.php?oldal=
sub*.php?op=
sub*.php?open=
sub*.php?OpenPage=
sub*.php?option=
sub*.php?pa=
sub*.php?pag=
sub*.php?panel=
sub*.php?path=
sub*.php?phpbb_root_path=
sub*.php?play=
sub*.php?pname=
sub*.php?pre=
sub*.php?qry=
sub*.php?recipe=
sub*.php?rub=
sub*.php?s=
sub*.php?sec=
sub*.php?secao=
sub*.php?secc=
sub*.php?seite=
sub*.php?sp=
sub*.php?str=
sub*.php?thispage=
sub*.php?u=
sub*.php?viewpage=
sub*.php?where=
sub*.php?z=
subcat.php?catID=
subcategories.asp?id=
subcategories.cfm?id=
subcategories.php?id=
subcategory-page.php?id=
subcategory.php?id=
suffering/newssummpopup.php?newscode=
summary.asp?PID=
summary.php?PID=
sup.php?id=
superleague/news_item.php?id=
superlinks/browse.php?id=
Supplied argument is not a valid PostgreSQL result
support/mailling/maillist/inc/initdb.php?absolute_path=
sw_comment.php?id=
tak/index.php?module=
tales.php?id=
tas/event.asp?id=
tas/event.php?id=
tecdaten/showdetail.asp?prodid=
tecdaten/showdetail.php?prodid=
tek9.asp?
tek9.cfm?
tek9.php?
tekken5/movelist.php?id=
template.asp?Action=Item&pid=
template.cfm?Action=Item&pid=
template.php?*[*]*=
template.php?a=
template.php?Action=Item&pid=
template.php?addr=
template.php?basepath=
template.php?base_dir=
template.php?c=
template.php?choix=
template.php?cont=
template.php?content=
template.php?corpo=
template.php?dir=
template.php?doshow=
template.php?e=
template.php?f=
template.php?goto=
template.php?h=
template.php?header=
template.php?ID=
template.php?ir=
template.php?k=
template.php?lang=
template.php?left=
template.php?load=
template.php?menue=
template.php?mid=
template.php?mod=
template.php?name=
template.php?nivel=
template.php?op=
template.php?opcion=
template.php?pag=
template.php?page=
template.php?pagina=
template.php?panel=
template.php?param=
template.php?path=
template.php?play=
template.php?pre=
template.php?qry=
template.php?ref=
template.php?s=
template.php?secao=
template.php?second=
template.php?section=
template.php?seite=
template.php?sekce=
template.php?showpage=
template.php?sp=
template.php?str=
template.php?t=
template.php?texto=
template.php?thispage=
template.php?tipo=
template.php?viewpage=
template.php?where=
template.php?y=
template1.php?id=
templet.asp?acticle_id=
templet.php?acticle_id=
test.php?page=
theater-show.php?id=
theme.php?id=
things-to-do/detail.asp?id=
things-to-do/detail.php?id=
thread.php/id=
today.asp?eventid=
today.php?eventid=
tools/print.asp?id=
tools/print.php?id=
tools/send_reminders.php?includedir=
tools/tools_cat.php?c=
top/store.php?cat_id=
top10.php?cat=
topic.asp?ID=
topic.cfm?ID=
topic.php?ID=
TopResources.php?CategoryID=
touchy/home.php?cat=
tour.php?id=
tourdetail.php?id=
tourism/details.php?id=
toynbeestudios/content.asp?id=
toynbeestudios/content.php?id=
trackback.php?id=
trade/listings.php?Id=
tradeCategory.php?id=
trailer.asp?id=
trailer.php?id=
trailer_detail.php?id=
trainers.php?id=
transcript.php?id=
trillian.ini
trvltime.php?id=
tuangou.asp?bookid=
tuangou.cfm?bookid=
tuangou.php?bookid=
tutorial.php?articleid=
tutorials/view.php?id=
type.asp?iType=
type.cfm?iType=
type.php?iType=
UBB.threads")|(inurl:login.php "ubb")
UebiMiau" -site:sourceforge.net
Ultima Online loginservers
Unreal IRCd
updatebasket.asp?bookid=
updatebasket.cfm?bookid=
updatebasket.php?bookid=
updates.asp?ID=
updates.cfm?ID=
updates.php?ID=
usar/productDetail.php?prodID=
usb/devices/showdev.asp?id=
usb/devices/showdev.php?id=
used/cardetails.php?id=
user/AboutAwardsDetail.php?ID=
users/view.php?id=
USG60W|USG110|USG210|USG310|USG1100|USG1900|USG2200|"ZyWALL110"|"ZyWALL310"|"ZyWALL1100"|ATP100|ATP100W|ATP200|ATP500|ATP700|ATP800|VPN50|VPN100|VPN300|VPN000|"FLEX")
v/showthread.php?t=
vb/showthread.php?p=
vb/showthread.php?t=
venue-details.php?id=
veranstaltungen/detail.asp?id=
veranstaltungen/detail.php?id=
video.php?content=
video.php?id=
videos/view.php?id=
view-event.asp?id=
view-event.php?id=
view.asp?cid=
view.asp?id=
view.asp?pageNum_rscomp=
view.cfm?cid=
view.php?*[*]*=
view.php?adresa=
view.php?b=
view.php?body=
view.php?channel=
view.php?chapter=
view.php?choix=
view.php?cid=
view.php?cmd=
view.php?content=
view.php?disp=
view.php?get=
view.php?go=
view.php?goFile=
view.php?goto=
view.php?header=
view.php?id=
view.php?incl=
view.php?ir=
view.php?ki=
view.php?lang=
view.php?load=
view.php?loader=
view.php?mid=
view.php?middle=
view.php?mod=
view.php?oldal=
view.php?option=
view.php?pag=
view.php?page=
view.php?pageNum_rscomp=
view.php?panel=
view.php?pg=
view.php?phpbb_root_path=
view.php?pollname=
view.php?pr=
view.php?qry=
view.php?recipe=
view.php?redirect=
view.php?sec=
view.php?secao=
view.php?seccion=
view.php?second=
view.php?seite=
view.php?showpage=
view.php?sp=
view.php?str=
view.php?to=
view.php?type=
view.php?u=
view.php?user_id=
view.php?var=
View.php?view=
view.php?v_id=
view.php?where=
view/7/9628/1.html?reply=
viewapp.asp?id=
viewapp.php?id=
viewcart.asp?CartId=
viewCart.asp?userID=
viewcart.cfm?CartId=
viewCart.cfm?userID=
viewcart.php?CartId=
viewCart.php?userID=
viewCat_h.asp?idCategory=
viewCat_h.cfm?idCategory=
viewCat_h.php?idCategory=
viewevent.asp?EventID=
viewevent.cfm?EventID=
viewevent.php?EventID=
viewevent.php?id=
viewitem.asp?recor=
viewitem.cfm?recor=
viewitem.php?recor=
viewmedia.php?prmMID=
viewphoto.php?id=
ViewPodcast.php?id=
viewPrd.asp?idcategory=
viewPrd.cfm?idcategory=
viewPrd.php?idcategory=
ViewProduct.asp?misc=
ViewProduct.cfm?misc=
viewproduct.php?id=
ViewProduct.php?misc=
viewproduct.php?prod=
viewproducts.php?id=
viewprofile.php?id=
viewshowdetail.php?id=
viewstore.php?cat_id=
viewthread.asp?tid=
viewthread.php?tid=
viewtopic.php?id=
viewtopic.php?pid=
view_article.php?id=
view_author.asp?id=
view_author.php?id=
view_cart.asp?title=
view_cart.cfm?title=
view_cart.php?title=
view_company.php?id=
view_detail.asp?ID=
view_detail.cfm?ID=
view_detail.php?ID=
view_event.php?eid=
view_faq.php?id=
view_item.asp?id=
view_item.asp?item=
view_item.php?id=
view_item.php?item=
view_items.asp?id=
view_items.php?id=
view_newsletter.asp?id=
view_newsletter.php?id=
view_product.php?id=
view_ratings.php?cid=
view_songs.php?cat_id=
villa_detail.php?id=
volunteers/item.php?id=
voteList.asp?item_ID=
voteList.cfm?item_ID=
voteList.php?item_ID=
wamp_dir/setup/yesno.phtml?no_url=
warning "error on line" php sablotron
WebLog Referrers
website.php?id=
weekly/story.php?story_id=
Welcome to ntop!
what***elieveb.php?id=
whatsnew.asp?idCategory=
whatsnew.cfm?idCategory=
whatsnew.php?idCategory=
where/details.php?id=
WhitsundaySailing.php?id=
wiki/pmwiki.asp?page****=
wiki/pmwiki.php?page****=
Windows 2000 web server error messages
worklog/task.php?id=
workshopview.php?id=
worthies/details.php?id=
WsAncillary.asp?ID=
WsAncillary.cfm?ID=
WsAncillary.php?ID=
WsPages.asp?ID=noticiasDetalle.asp?xid=
WsPages.cfm?ID=HP
WsPages.php?ID=noticiasDetalle.php?xid=
wwdsemea/default.asp?ID=
www/index.asp?page=
www/index.php?page=
wwwboard WebAdmin inurl:passwd.txt wwwboard|webadmin
WWWThreads")|(inurl:"wwwthreads/login.php")|(inurl:"wwwthreads/login.pl?Cat=")
x/product.php?productid=
xcart/home.php?cat=
xcart/product.php?productid=
XOOPS Custom Installation
yacht_search/yacht_view.asp?pid=
yacht_search/yacht_view.php?pid=
yarndetail.php?id=
YZboard/view.asp?id=
YZboard/view.php?id=
zb/view.asp?uid=
zb/view.php?uid=
zentrack/index.php?configFile=
[WFClient] Password= filetype:ica
\"index of /private\" -site:net -site:com -site:org
\"Powered by 123LogAnalyzer\"
\"Powered by phpBB\" inurl:\"index.php?s\" OR inurl:\"index.php?style\"
_news/news.asp?id=
_news/news.php?id=
åÏå ãÌãæÚÉ ÏæÑßÇÊ ÃÎÑì :
“Windows XP Professional” 94FBR