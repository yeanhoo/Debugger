@echo off

FOR /R %dir% %%d IN (vc60.pdb vc90.pdb *.exp *.obj *.pch *.idb *.ncb *.opt *.plg *.res *.sbr *.ilk *.aps *.sdf *.temp *.dcu *.bsc *.ipch ) DO DEL /f /s /q "%%d" 2>nul
 
FOR /R . %%d IN (.) DO rd /s /q "%%d\Debug" 2>nul
 
FOR /R . %%d IN (.) DO rd /s /q "%%d\Release" 2>nul
