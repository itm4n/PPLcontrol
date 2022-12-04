# PPLcontrol

## Description

This tools allows you to list protected processes, get the protection level of a specific process, or set an arbitrary protection level. For more information, you can read this blog post: [Debugging Protected Processes](http://192.168.140.131:4000/debugging-protected-processes/).

## Usage

### 1. Download the MSI driver

You can get a copy of the MSI driver `RTCore64.sys` here: [PPLKiller/driver](https://github.com/RedCursorSecurityConsulting/PPLKiller/tree/master/driver).

### 2. Install the MSI driver

__Disclaimer:__ it goes without saying that you should never install this driver on your host machine. __Use a VM!__

```console
C:\Temp>sc.exe create RTCore64 type= kernel start= auto binPath= C:\PATH\TO\RTCore64.sys DisplayName= "Micro - Star MSI Afterburner"
C:\Temp>net start RTCore64
```

### 3. Use PPLcontrol

List protected processes.

```console
C:\Temp>PPLcontrol.exe list
```

Get the protection level of a specific process.

```console
C:\Temp>PPLcontrol.exe get 1234
```

Set an arbitrary protection level.

```console
C:\Temp>PPLcontrol.exe set 1234 PPL WinTcb
```

Protect a non-protected process.

```console
C:\Temp>PPLcontrol.exe protect 1234 PPL WinTcb
```

Unprotect a protected process.

```console
C:\Temp>PPLcontrol.exe unprotect 1234
```

### 4. Uninstall the driver

```console
C:\Temp>net stop RTCore64
C:\Temp>sc.exe delete RTCore64
```

## Build

1. Open the solution in Visual Studio.
2. Select `Release/x64` (`x86` is not supported and will probably never be).
3. Build solution

## Credit

- [@aceb0nd](https://twitter.com/aceb0nd) for the tool [PLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)
- [@aionescu](https://twitter.com/aionescu) for the article [Protected Processes Part 3: Windows PKI Internals (Signing Levels, Scenarios, Root Keys, EKUs & Runtime Signers](https://www.alex-ionescu.com/?p=146](https://www.alex-ionescu.com/?p=146)
