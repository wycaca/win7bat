@Echo Off
Title win7一键优化
::by 卡饭 我呀擦擦

set TempFile_Name=%SystemRoot%\System32\BatTestUACin_SysRt%Random%.batemp
( echo "BAT Test UAC in Temp" >%TempFile_Name% ) 1>nul 2>nul
if exist %TempFile_Name% (
del %TempFile_Name% 1>nul 2>nul
GOTO menu
) else (
GOTO admin
)

:menu
ECHO =============================================================================
ECHO                            Windows 7 一键优化                           
ECHO  #++++++++++++++++++++++++++++++++++++#+++++++++++++++++++++++++++++++++++#
ECHO  # 1、去除快捷方式小箭头              # 2、去除快捷方式字样               #
ECHO  # 3、右键菜单添加显示后缀隐藏文件    # 4、win7离开模式                   #
ECHO  # 5、去除休眠文件                    # 6、退出程序时自动清理内存中的DLL  #
ECHO  # 7、关闭程序兼容性助手              # 8、关闭UAC                        #
ECHO  # 9、清理右键新建项目                # 10、停止系统还原与备份            #
ECHO  # 11、清除右键显卡菜单项             # 12、去除操作中心小旗子            #
ECHO  # 13、任务栏显示星期几               # 14、关闭自动播放                  #
ECHO  # 17、右键菜单添加用记事本打开       # 18、右键菜单添加管理员取得所有权  #
ECHO  # 19、开机磁盘扫描等待时间(默认2秒)  # 20、加快菜单与任务栏预览的显示速度#
ECHO  # 21、关闭DEP                        # 22、清除右键菜单还原以前的版本    #
ECHO  # 23、清除右键菜单兼容性疑难解答     # 24、执行关机时强制退出应用程序    #
ECHO  #++++++++++++++++++++++++++++++++++++#+++++++++++++++++++++++++++++++++++#

ECHO =============================================================================
choice /c ynb /n /m "你确定优化以上内容?输入y继续,n退出,b备份/恢复"
pause
if errorlevel 3 goto 备份/还原注册表
if errorlevel 2 goto 退出
if errorlevel 1 goto 开始  

:开始
::去除快捷方式小箭头
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v 29 /d "%systemroot%\system32\imageres.dll,196" /t reg_sz /f

::去除快捷方式字样
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v link /t REG_BINARY /d 00000000 /f

::去除休眠文件
powercfg -h off

::win7离开模式
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v AwayModeEnabled /t REG_DWORD /d 00000001 /f

::右键菜单添加显示后缀隐藏文件
>"%windir%\SuperHidden.vbs" echo Dim WSHShell
>>"%windir%\SuperHidden.vbs" echo Set WSHShell = WScript.CreateObject("WScript.Shell")
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCR\CLSID\{00000000-0000-0000-0000-000000000012}\Instance\InitPropertyBag\CLSID", "{13709620-C279-11CE-A49E-444553540000}", "REG_SZ"
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCR\CLSID\{00000000-0000-0000-0000-000000000012}\Instance\InitPropertyBag\method", "ShellExecute", "REG_SZ"
>>"%windir%\SuperHidden.vbs" echo if WSHShell.RegRead("HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt") = 0 then
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden", "0", "REG_DWORD"
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden", "2", "REG_DWORD"
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt", "1", "REG_DWORD"
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCR\CLSID\{00000000-0000-0000-0000-000000000012}\Instance\InitPropertyBag\command", "显示扩展名及文件", "REG_SZ"
>>"%windir%\SuperHidden.vbs" echo WSHShell.SendKeys "{F5}e"
>>"%windir%\SuperHidden.vbs" echo else
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden", "1", "REG_DWORD"
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden", "1", "REG_DWORD"
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt", "0", "REG_DWORD"
>>"%windir%\SuperHidden.vbs" echo WSHShell.RegWrite "HKCR\CLSID\{00000000-0000-0000-0000-000000000012}\Instance\InitPropertyBag\command", "隐藏扩展名及文件", "REG_SZ"
>>"%windir%\SuperHidden.vbs" echo WSHShell.SendKeys "{F5}e"
>>"%windir%\SuperHidden.vbs" echo end if
>>"%windir%\SuperHidden.vbs" echo Set WSHShell = Nothing
>>"%windir%\SuperHidden.vbs" echo WScript.Quit(0)
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "%temp%\__.reg" >nul
for /f "tokens=2 delims==" %%. in ('find/i "HideFileExt" "%temp%\__.reg"') do set v=%%~.
del "%temp%\__.reg"
set v=%v:~-1%
if %v% equ 0 set vv=隐藏扩展名及文件
if %v% equ 1 set vv=显示扩展名及文件
>"%temp%\_.reg" echo REGEDIT4
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\SuperHidden]
>>"%temp%\_.reg" echo @="{00000000-0000-0000-0000-000000000012}"
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\CLSID\{00000000-0000-0000-0000-000000000012}\InProcServer32]
>>"%temp%\_.reg" echo @=hex(2):25,53,79,73,74,65,6d,52,6f,6f,74,25,5c,73,79,73,74,65,6d,33,32,5c,73,\
>>"%temp%\_.reg" echo   68,64,6f,63,76,77,2e,64,6c,6c,00
>>"%temp%\_.reg" echo "ThreadingModel"="Apartment"
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\CLSID\{00000000-0000-0000-0000-000000000012}\Instance]
>>"%temp%\_.reg" echo "CLSID"="{3f454f0e-42ae-4d7c-8ea3-328250d6e272}"
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\CLSID\{00000000-0000-0000-0000-000000000012}\Instance\InitPropertyBag]
>>"%temp%\_.reg" echo "method"="ShellExecute"
>>"%temp%\_.reg" echo "Param1"="SuperHidden.vbs"
>>"%temp%\_.reg" echo "CLSID"="{13709620-C279-11CE-A49E-444553540000}"
>>"%temp%\_.reg" echo "command"="%vv%"
regedit /s "%temp%\_.reg"
del /f /q "%temp%\_.reg"
echo.&echo 已添加右键 %vv%

::退出程序时自动清理内存中的DLL
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v AlwaysUnloadDll /t REG_DWORD /d 00000001 /f

::关闭程序兼容性助手
sc stop PcsSvc 
sc config PcsSvc start= disabled

::关闭UAC
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 00000000 /f

::清理右键新建项目
reg delete HKEY_CLASSES_ROOT\.bmp\ShellNew /f
reg delete HKEY_CLASSES_ROOT\.rar\ShellNew /f
reg delete HKEY_CLASSES_ROOT\.zip\ShellNew /f
reg delete HKEY_CLASSES_ROOT\Briefcase\ShellNew /f
reg delete HKEY_CLASSES_ROOT\.xdp\AcroExch.XDPDoc\ShellNew /f
reg delete HKEY_CLASSES_ROOT\.jnt\jntfile\ShellNew /f
reg delete HKEY_CLASSES_ROOT\.contact\ShellNew /f
reg delete HKEY_CLASSES_ROOT\.rtf\ShellNew /f
reg delete HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew /f

::停止系统还原与备份
net stop SDRSVC

::清除右键显卡菜单项
regsvr32 /u igfxpph.dll /s
regsvr32 /u atiacmxx.dll /s
regsvr32 /u nvcpl.dll /s

::去除操作中心
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /d 1 /t REG_DWORD /f

::任务栏显示星期几
reg add "HKEY_CURRENT_USER\Control Panel\International" /v "sLongDate" /d "yyyy'年'M'月'd'日', dddd" /t REG_SZ /f
reg add "HKEY_CURRENT_USER\Control Panel\International" /v "sShortDate" /d "yyyy/M/d/ddd" /t REG_SZ /f

::关闭自动播放
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /d 255 /t REG_DWORD /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /d 255 /t REG_DWORD /f
taskkill /f /im explorer.exe
start %systemroot%\explorer

::右键菜单添加用记事本打开
reg add "HKEY_CLASSES_ROOT\*\shell\Noteped" /ve /d 使用记事本打开 /f
reg add "HKEY_CLASSES_ROOT\*\shell\Noteped\command" /ve /d "notepad.exe %%1" /f

::右键菜单添加管理员取得所有权
>"%temp%\_.reg" echo Windows Registry Editor Version 5.00
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\*\shell\runas]
>>"%temp%\_.reg" echo @="管理员取得所有权"
>>"%temp%\_.reg" echo "NoWorkingDirectory"=""
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\*\shell\runas\command]
>>"%temp%\_.reg" echo @="cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F"
>>"%temp%\_.reg" echo "IsolatedCommand"="cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F"
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\exefile\shell\runas2]
>>"%temp%\_.reg" echo @="管理员取得所有权"
>>"%temp%\_.reg" echo "NoWorkingDirectory"=""
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\exefile\shell\runas2\command]
>>"%temp%\_.reg" echo @="cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F"
>>"%temp%\_.reg" echo "IsolatedCommand"="cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F"
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\Directory\shell\runas]
>>"%temp%\_.reg" echo @="管理员取得所有权"
>>"%temp%\_.reg" echo "NoWorkingDirectory"=""
>>"%temp%\_.reg" echo [HKEY_CLASSES_ROOT\Directory\shell\runas\command]
>>"%temp%\_.reg" echo @="cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t"
>>"%temp%\_.reg" echo "IsolatedCommand"="cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t"
regedit /s "%temp%\_.reg"
del /f /q "%temp%\_.reg"

::开机磁盘扫描等待时间
chkntfs /t:2

::加快菜单与任务栏预览的显示速度
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /d 0 /t REG_SZ /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseHoverTime /d 0 /t REG_SZ /f

::清除右键菜单兼容性疑难解答
reg delete "HKEY_CLASSES_ROOT\lnkfile\shellex\ContextMenuHandlers\Compatibility" /f
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\Compatibility" /f
reg delete "HKEY_CLASSES_ROOT\batfile\ShellEx\ContextMenuHandlers\Compatibility" /f

::清除右键菜单还原以前的版本
reg delete "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f
reg delete "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f

::关闭DEP
bcdedit /set nx alwaysoff

::执行关机时强制退出应用程序
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v WaitToKillAppTimeout /d 1000 /t REG_SZ /f

@echo.一键优化操作已完成,重启生效
pause>nul
::by 卡饭 我呀擦擦

:admin
CLS
ECHO 操作失败。
echo 请右键“以管理员身份运行”
ECHO 按任意键退出...
PAUSE >nul
exit

:退出
exit

:备份/还原注册表
ECHO.
ECHO.
ECHO    **********************************
ECHO.
ECHO             备份/还原注册表
ECHO    (能还原大部分修改，备份路径在C盘)
ECHO.
ECHO                1.备份
ECHO.
ECHO                2.还原
ECHO.
ECHO    **********************************
ECHO.
ECHO.
Choice /C 12 /N /M 选择（1、2）：
If ErrorLevel 1 If Not ErrorLevel 2 Goto 备份注册表
If ErrorLevel 2 If Not ErrorLevel 3 Goto 还原注册表
:备份注册表
regedit /E c:/注册表备份.reg
@echo.操作已完成,按任意键返回主菜单
pause>nul
cls
GOTO menu
:还原注册表
regedit /s c:/注册表备份.reg
@echo.操作已完成,按任意键返回主菜单
pause>nul
cls
GOTO menu
