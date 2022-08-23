---
layout: post
title:  "Reverse Updater.exe"
---


# Overview

Updater.exe is C++ executable and attempts to create a process for the target exe in “0.0.0.0” folder of its current path.

The folder **0.0.0.0** might have an executable, if it does, then it is executed by Updater.exe which results in a new process. The target exe was not found in the “0.0.0.0” folder, so it’s unclear what the malware did after executing the exe in the folder.

---

# Capability

- Look up directories in current path.
- Create a new process for the target executable.

---

# Full Disassembly Analysis

The analysis has been performed using IDA Pro. Both disassembly and pseudocode have been analyzed.

See Figure 1 for the disassembly of the entry point.

![Figure 1 entry point of updater.exe](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled.png)

*Figure 1 entry point of updater.exe*

In the entry point, a function “sub_A61CA0” is called with two arguments *lpCmdLine* & *nShowCmd*. The second argument *nShowCmd* is ignored in the function, it’s not used.

In Figure 2, the pseudocode of the function sub_A61CA0 is shown. There’s a call to function **sub_A61860**, it takes a string object as an argument, once the function returns, the string object will contain the target path. The target path is where the program expects the target exe to be located.

![Figure 2: This function contains the main functionality of the program](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%201.png)

*Figure 2: This function contains the main functionality of the program*

![Figure 3: sub_A61860 get target path](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%202.png)

*Figure 3: sub_A61860 get target path*

In Figure 3, first a string object is created with value **0.0.0.0** then another function **sub_A627A0** is called and it will place the current directory of Updater.exe in the first argument.

**sub_A61200** is a string concat function. It will concat the current directory and the string “\\*”, the result is stored in the first argument of the function, and it’s the search path where the directories are looked up. *FindFirstFileW* function will get the first file in the search path and *FindNextFileW* is called in the while loop condition to go through all files in the search path as shown in the Figure 4:

![Figure 4: Lookup directories in the search path.](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%203.png)

*Figure 4: Lookup directories in the search path.*

The first condition in the *Dowhile* loop checks whether the flag **0x10** (See Figure 5) is set in *FindFileData.dwFileAttributes*. It checks whether the *fileData* belongs to a file or a folder. If it’s a folder, then the condition is true, otherwise false.

![Figure 5: File Attribute](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%204.png)

*Figure 5: File Attribute*

The condition at Line 45 is always true and the else block never executes:

1. `*(v6 - 4)` always returns one. It never changes.
2. The value of ***ecx*** is set to `*(v6 - 16)`, so this is also true.

The virtual function at line 44 is called before the condition at line 45, but it's empty, and it has only one instruction **`mov  eax, ecx`**. It moves the value of ***ecx*** register into ***eax***, so this means now the value of ***eax*** is equal to `*(v6 - 16)`. In this way, the two conditions in the if statement are always true, so the else block never executes. In this way, the target exe is always inside folder **0.0.0.0**

![Figure 6: String virtual function at offset 16](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%205.png)

*Figure 6: String virtual function at offset 16*

The function **sub_ED1200** (See Figure 7) will concat the current directory string with a backslash and then the folder name “0.0.0.0” is appended to the path. The result string (target directory) is stored in the pointer of argument 1, and it is also returned.

![Figure 7: The bottom code of function to get target directory.](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%206.png)

*Figure 7: The bottom code of function to get target directory.*

In Figure 8, the pseudocode of sub_AE1CA0 is shown. After retrieving the target directory, the target exe name is fetched in another function call, but it’s the same as the name of **Updater.exe**. Then a backslash is appended to the target directory and later the exe name is also appended. The resultant string is **<currentDir>\\0.0.0.0\\Updater.exe**

**sub_ED10C0** creates a string object for the command line string passed in the second argument. The target exe path is then passed to **sub_ED2C90** function as an argument and the command line string object is passed in the second argument.

![Figure 8: The pseudocode of sub_AE1CAO. This function is called in Winmain.](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%207.png)

*Figure 8: The pseudocode of sub_AE1CAO. This function is called in Winmain.*

In figure 9 the function **sub_AE2C90** is responsible for creating the target process only the first argument is interesting because it contains the path of the target exe. The second argument is not used, but the destructor is called for it before returning. In Figure 10, the path of the target exe can be seen because the exe is being debugged in IDA.

In Figure 9, the line 32 shows that the address of string *lpApplicationName* is moved to **v5** (eax register). Then the **v5** (eax register) is passed to *CreateProcessW* as the first argument to create the target process. The destructors for the string objects are called at the bottom of the function and the function returns. The control (EIP) goes back to sub_AE1CAO, the two virtual destructors are called for string objects and the function returns to *WinMain* and the program exits.

![Figure 9: Pseudocode of function sub_AE2C90. Creates the target process.](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%208.png)

*Figure 9: Pseudocode of function sub_AE2C90. Creates the target process.*

![Figure 10: lpApplicationName argument in sub_AE2C90 function](https://raw.githubusercontent.com/hamad-she/hamad-she.github.io/master/_posts/imgs/updater_exe/Untitled%209.png)

*Figure 10: lpApplicationName argument in sub_AE2C90 function*


