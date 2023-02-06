@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc findsysmon.c
move /y findsysmon.obj findsysmon.o
dumpbin /disasm findsysmon.o > findsysmon.disasm

