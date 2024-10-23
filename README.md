# Korosu - 殺す
A varient of SadBoy.Terminator - Uses the vulnerable 'Zemana Antimalware' driver to kill EDR.  
Bundles the (***widely detected***) vulnerable terminator.sys driver into a windowless C++ executable.

# Flow
1.) Requests admin privilege (required)  
2.) Creates 'Terminator' service  
3.) Drops Terminator.sys in %Temp%  
4.) Loads Terminator.sys  
5.) Scans and kills all EDR via proces name matching (5s Loop).  

*Compile Command:*
```
cl /EHsc /FeKorosu.exe Korosu.cpp Korosu.res /link kernel32.lib user32.lib advapi32.lib shell32.lib /SUBSYSTEM:WINDOWS
```
