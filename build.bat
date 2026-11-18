@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem 一键编译《不问凡尘》存档修改器（只需要 Windows 自带的 .NET Framework 4.x，不用装 Visual Studio）
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
set OUT=WorldApartSaveEditor.exe
set RES=/resource:talent_db.tsv,talent_db.tsv /resource:npc_db.tsv,npc_db.tsv /resource:daopath_db.tsv,daopath_db.tsv /resource:item_db.tsv,item_db.tsv /resource:affix_db.tsv,affix_db.tsv /resource:attr_db.tsv,attr_db.tsv /resource:misc_db.tsv,misc_db.tsv /resource:pill_db.tsv,pill_db.tsv
if exist donate_qr.png set RES=%RES% /resource:donate_qr.png,donate_qr.png
"%CSC%" /nologo /target:winexe /optimize+ /out:%OUT% /r:System.Windows.Forms.dll /r:System.Drawing.dll %RES% Program.cs
if errorlevel 1 (echo 编译失败 & pause & exit /b 1)
echo 编译完成：%OUT%