---
layout: post
title:  "Sdd.exe (backdoor)"
---

A stealthy backdoor executable called ‘sdd.exe’ which the backdoor enables the intruder to execute the command remotely through the HTTP requests. The backdoor uses a special field name in HTTP body to carry the command and capture the execution output, both requests and response are base64 encoded. Moreover, the ‘sdd.exe’ is an executable has been written in C# .NET ,and it has a full capabilities such as Upload, Download, command and Run dll.

Through the analysis of the backdoor, the following are the main functionalities and identified behavior (e881e8277154dbc53bfe7910979c27d1):

- Appellations sdd.exe is a heavily obfuscated and compiled backdoor written in C#, encrypted using AES and encoded using Base64.
- The backdoor’s classes and functions names have been obfuscated as well to thwart the static analysis of the backdoor; usually named after random names that has nothing to do with the functions and classes purposes.
- Appellations sdd.exe’s code entry point, as shown in figure (1).
- 

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled.png)

Figure 1 Entry Point

---

- Figure (2 & 3), shows the communication mechanism in this backdoor is established over an HTTP listener on port 80 at the infected machine, where it enables the adversary to send and request base64 payloads through HTTP requests. It’s worth noting that several function has been obfuscated and have rewritten in their original format as comments at the code-snippet. Moreover, a 404 error will be present if the backdoor is unreachable by the adversary, as shown in figure (4).

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%201.png)

Figure 2 C2 Communication Machanis

---

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%202.png)

Figure 3 Rest of the C2 Communication Mechanism

---

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%203.png)

Figure 4 404 - File or directory not found

- Figure (5) shows the HTTP payload request handling mechanism in the backdoor executes various switch cases for enabling the adversary to do multiple functionalities (Figure 5)

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%204.png)

Figure 5 Request Handling Mechanism

the following are the list of these functionalities:

- Upload files.

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%205.png)

Figure 6 File Upload

- Download files through WeatherRelease ( ).

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%206.png)

Figure 7 File Download

- Use shell command line if the Boolean condition is true to send commands through payloads.

 

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%207.png)

Figure 8 Command Execution Through the Cmd

- Sends a heartbeat[[1]](https://www.notion.so/Sdd-exe-backdoor-e18cb68dc47344b390d0e4d950ef414a) through: http://localhost/TEMPORARY_LISTEN_ADDRESSES/wOxhuoSBgpGcnLQZxipa
- The ability to load DLLs through Rundll[[2]](https://www.notion.so/Sdd-exe-backdoor-e18cb68dc47344b390d0e4d950ef414a) or any additional payload as payloads. The loaded payloads are supposed to be heavily obfuscated through XOR and base64 encoding mechanism. Here are some technical details about this mechanism and payload handling:
    - The received payload will initiate the deobfuscation mechanism starting by decoding the payload from base64, then decrypting the payload from AES in variable array2 through the AES key in Figure (10).

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%208.png)

Figure 9 Encoding Mechanism

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%209.png)

Figure 10 AES Decryption key

- The expected payload to be received by the backdoor should be structure as follows, as shown in figure (11) and the code snippet in figure (12 & 13):
    - 4 bytes: command string size
- X bytes: command string
- 4 bytes: command string arguments size
- X bytes: command string arguments

             - 4 bytes: command Type

              - 4 bytes: string size

               - X bytes: string

               - 4 bytes: another structure size

                - X bytes: another structure

- 4 bytes: command string size

- X bytes: command string
- 4 bytes: command string arguments size
- X bytes: command string arguments

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%2010.png)

Figure 11 Payload Structure

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%2011.png)

Figure 12 Code Snippet of the Payload Structure

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%2012.png)

Figure 13 Code Snippet of the Payload Structure

- The DLL loader function in the memory is done through the Load( ) in figure (14).

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%2013.png)

Figure 14 DLL loader function in the memory

- The following is Appellations sdd.exe’s AES encryption algorithm. This function decrypts the DLL code in the memory using this function through: internal static byte[] script_hair_room(byte[] madtossokayvarious), as shown in figure (15).

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%2014.png)

Figure 15 Decryption Function

Moreover, the AES encryption algorithm in this backdoor uses                                        16 block key, as shown in figure (16).

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%2015.png)

Figure 16 Encryption Key

In addition, as shown in figure (17), childburden( ) handles the DLL payloads that fail to load through AppDomain and AsemblyResolve[[3]](https://www.notion.so/Sdd-exe-backdoor-e18cb68dc47344b390d0e4d950ef414a) events. If the handling function succeed, the loaded DLL will be decrypted and loaded again through the function call in allowbasic.Jazz_inputpaper ( ) that calls for the DLL decryption function script_hair_room ( ).

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Sdd_backdoor/Untitled%2016.png)

Figure 17 DLL Handling

---

 Table (1) addresses the observed TTPs utilized by this backdoor.

Table 1 TTPs

| Tactic | Technique | Procedure |
| --- | --- | --- |
| Privilege Escalation | Abuse Elevation Control Mechanism: Bypass User Account Control | Place the DLL backdoor under IIS Modules, as well as loading additional DLL payloads using Rundll. |
| Defense Evasion | Deobfuscate/Decode Files or Information | Using AES encryption and Base64 encoding. |
| Command and Control | Application Layer Protocol: Web Protocols | Adversary communicates with the backdoor through HTTP POST. |