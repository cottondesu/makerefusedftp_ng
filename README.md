makerefusedftp_ng
=================
Usage  
-------  
ruby -Ku makerefusedftp_ng.rb <log file of vsftpd format>  
  
  
log file of vsftpd format  
-------  
day Mon dd hh:mm:ss yyyy [pid xxxx] CONNECT: Client "xxx.xxx.xxx.xxx"  
day Mon dd hh:mm:ss yyyy [pid xxxx] [loginusername] FAIL LOGIN: Client "xxx.xxx.xxx.xxx"  
day Mon dd hh:mm:ss yyyy [pid xxxx] CONNECT: Client "xxx.xxx.xxx.xxx"  
day Mon dd hh:mm:ss yyyy [pid xxxx] [loginusername] OK LOGIN: Client "xxxx.xxx.xxx.xxx"  
  
log exsample  
-------  
Sun Oct 21 09:03:37 2012 [pid 6477] CONNECT: Client "222.222.222.222"  
Sun Oct 21 09:03:39 2012 [pid 6476] [Administrator] FAIL LOGIN: Client "222.222.222.222"  
Sun Oct 21 09:03:42 2012 [pid 6476] [Administrator] FAIL LOGIN: Client "222.222.222.222"  
Sun Oct 21 10:02:36 2012 [pid 6545] CONNECT: Client "111.111.111.111"  
Sun Oct 21 10:02:36 2012 [pid 6544] [testuser] OK LOGIN: Client "111.111.111.111"  

And outputs the HTML file to the IP and the unauthorized access to log analysis
