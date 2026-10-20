Unicode true

; This file must stay UTF-8 *with* a byte order mark. Without one, makensis
; reads it in the system's ANSI code page and every accented string comes out
; garbled ("PortÃ©e"). installer_test.go checks it.

####
## SyslogStudio Installer
##
## Features:
##   - Dual install mode: per-user (no admin) or all-users (admin via UAC);
##     only an all-users install can run as a Windows service, and the
##     installer says so where the choice is made
##   - MUI2 modern interface with language selection (English / French)
##   - Optional desktop shortcut on finish page
##   - Launch after install option
##   - Start menu group with app + uninstall shortcuts
##   - Clean uninstaller with auto-elevation for all-users installs
##   - Proper Add/Remove Programs registry entries
##   - WebView2 runtime check and install
##   - DPI-aware, architecture-aware (amd64 / arm64)
##
## Silent install:
##   SyslogStudio-amd64-installer.exe /S              (per-user)
##   SyslogStudio-amd64-installer.exe /S /allusers     (all-users, needs admin)
####

; ====================================================================
;  Override wails default before including wails_tools.nsh
; ====================================================================
!define REQUEST_EXECUTION_LEVEL "user"

!include "wails_tools.nsh"
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "StrFunc.nsh"

; StrFunc functions must be declared before use (the uninstaller needs none).
${StrStr}

; The Windows service SyslogStudio can install (Settings > Background). It
; runs this very executable, so an update has to stop it to replace the file
; and start it again afterwards, and an uninstall has to remove it first.
!define SERVICE_NAME "SyslogStudio"
Var ServiceWasRunning

; ====================================================================
;  Version information
; ====================================================================
VIProductVersion "${INFO_PRODUCTVERSION}.0"
VIFileVersion    "${INFO_PRODUCTVERSION}.0"

VIAddVersionKey "CompanyName"     "${INFO_COMPANYNAME}"
VIAddVersionKey "FileDescription" "${INFO_PRODUCTNAME} Installer"
VIAddVersionKey "ProductVersion"  "${INFO_PRODUCTVERSION}"
VIAddVersionKey "FileVersion"     "${INFO_PRODUCTVERSION}"
VIAddVersionKey "LegalCopyright"  "${INFO_COPYRIGHT}"
VIAddVersionKey "ProductName"     "${INFO_PRODUCTNAME}"

; ====================================================================
;  General configuration
; ====================================================================
ManifestDPIAware true

Name "${INFO_PRODUCTNAME}"
OutFile "..\..\bin\${INFO_PROJECTNAME}-${ARCH}-installer.exe"
ShowInstDetails nevershow
ShowUninstDetails nevershow

; ====================================================================
;  Variables
; ====================================================================
Var InstMode      ; "user" or "allusers"
Var RadioUser
Var RadioAdmin
Var BoldFont
Var FinishText

; ====================================================================
;  MUI2 appearance
; ====================================================================
!define MUI_ICON "..\icon.ico"
!define MUI_UNICON "..\icon.ico"

!define MUI_ABORTWARNING

; Finish page: launch application
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_FINISHPAGE_RUN "$INSTDIR\${PRODUCT_EXECUTABLE}"
!define MUI_FINISHPAGE_RUN_TEXT "$(launch_app)"

; Finish page: desktop shortcut checkbox (reuses the "Show Readme" slot)
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(desktop_shortcut)"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION CreateDesktopShortcut
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED

; Finish page: the next step depends on the install mode (FinishPre)
!define MUI_FINISHPAGE_TEXT "$FinishText"
!define MUI_FINISHPAGE_TEXT_LARGE

; ====================================================================
;  Pages
; ====================================================================
!insertmacro MUI_PAGE_WELCOME
Page custom InstModeCreate InstModeLeave
!insertmacro MUI_PAGE_LICENSE "..\..\..\LICENSE"
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE DirLeave
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_PAGE_CUSTOMFUNCTION_PRE FinishPre
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; ====================================================================
;  Languages
; ====================================================================
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "French"

; ---- Installer strings ----

LangString scope_title       ${LANG_ENGLISH} "Installation Type"
LangString scope_title       ${LANG_FRENCH}  "Type d'installation"

LangString scope_subtitle    ${LANG_ENGLISH} "This choice decides whether ${INFO_PRODUCTNAME} can run as a Windows service."
LangString scope_subtitle    ${LANG_FRENCH}  "Ce choix décide si ${INFO_PRODUCTNAME} pourra fonctionner comme service Windows."

LangString scope_user        ${LANG_ENGLISH} "Install just for me"
LangString scope_user        ${LANG_FRENCH}  "Installer uniquement pour moi"

; The two descriptions line up point by point, so the differences stand out.
LangString scope_user_desc   ${LANG_ENGLISH} "•  In your profile, no administrator rights needed.$\r$\n•  Receives during your session, with its window open or in the background.$\r$\n•  Cannot run as a Windows service."
LangString scope_user_desc   ${LANG_FRENCH}  "•  Dans votre profil, sans droits administrateur.$\r$\n•  Reçoit pendant votre session, fenêtre ouverte ou en arrière-plan.$\r$\n•  Ne peut pas fonctionner comme service Windows."

LangString scope_admin       ${LANG_ENGLISH} "Install for all users"
LangString scope_admin       ${LANG_FRENCH}  "Installer pour tous les utilisateurs"

LangString scope_admin_desc  ${LANG_ENGLISH} "•  In Program Files, with administrator rights (Windows will ask for them).$\r$\n•  Receives during your session, with its window open or in the background.$\r$\n•  Can also run as a Windows service."
LangString scope_admin_desc  ${LANG_FRENCH}  "•  Dans Program Files, avec les droits administrateur (Windows les demandera).$\r$\n•  Reçoit pendant votre session, fenêtre ouverte ou en arrière-plan.$\r$\n•  Peut aussi fonctionner comme service Windows."

LangString scope_service     ${LANG_ENGLISH} "Windows service: ${INFO_PRODUCTNAME} receives from the moment the PC starts, even when nobody is signed in. It is set up after installing, in Settings > Background."
LangString scope_service     ${LANG_FRENCH}  "Service Windows : ${INFO_PRODUCTNAME} reçoit dès le démarrage du PC, même si personne n'est connecté. Il se met en place après l'installation, dans Paramètres › Arrière-plan."

LangString dir_no_service    ${LANG_ENGLISH} "The Windows service can only be installed from Program Files, which ordinary users cannot modify. Installed here, ${INFO_PRODUCTNAME} will only receive while someone is signed in.$\r$\n$\r$\nInstall here anyway?"
LangString dir_no_service    ${LANG_FRENCH}  "Le service Windows ne peut être installé que depuis Program Files, que les utilisateurs ordinaires ne peuvent pas modifier. Installé ici, ${INFO_PRODUCTNAME} ne recevra que pendant une session ouverte.$\r$\n$\r$\nInstaller ici quand même ?"

; The finish page's text box holds six lines with the two options below it:
; measured with its own font, these take five at most.
LangString finish_user       ${LANG_ENGLISH} "Installed for your account only.$\r$\n$\r$\nTo receive in the background from the moment you sign in: Settings > Background."
LangString finish_user       ${LANG_FRENCH}  "Installé pour votre compte uniquement.$\r$\n$\r$\nPour recevoir en arrière-plan dès l'ouverture de votre session : Paramètres › Arrière-plan."

LangString finish_allusers   ${LANG_ENGLISH} "Installed for all users.$\r$\n$\r$\nTo receive from the moment the PC starts, even when nobody is signed in, install the Windows service: Settings > Background."
LangString finish_allusers   ${LANG_FRENCH}  "Installé pour tous les utilisateurs.$\r$\n$\r$\nPour recevoir dès le démarrage du PC, même sans session ouverte, installez le service Windows : Paramètres › Arrière-plan."

LangString launch_app        ${LANG_ENGLISH} "Launch ${INFO_PRODUCTNAME}"
LangString launch_app        ${LANG_FRENCH}  "Lancer ${INFO_PRODUCTNAME}"

LangString desktop_shortcut  ${LANG_ENGLISH} "Create desktop shortcut"
LangString desktop_shortcut  ${LANG_FRENCH}  "Créer un raccourci sur le bureau"

LangString elevation_failed  ${LANG_ENGLISH} "Administrator rights were not granted, so ${INFO_PRODUCTNAME} cannot be installed for all users.$\r$\n$\r$\nTry again, or choose to install it just for you."
LangString elevation_failed  ${LANG_FRENCH}  "Les droits administrateur n'ont pas été accordés : ${INFO_PRODUCTNAME} ne peut pas être installé pour tous les utilisateurs.$\r$\n$\r$\nRéessayez, ou choisissez de l'installer uniquement pour vous."

LangString remove_data       ${LANG_ENGLISH} "Do you also want to remove application data (settings, log database)?"
LangString remove_data       ${LANG_FRENCH}  "Voulez-vous aussi supprimer les données de l'application (paramètres, base de logs) ?"

LangString un_need_admin     ${LANG_ENGLISH} "This application was installed for all users.$\r$\nAdministrator rights are needed to uninstall.$\r$\n$\r$\nRestart with elevated privileges?"
LangString un_need_admin     ${LANG_FRENCH}  "Cette application a été installée pour tous les utilisateurs.$\r$\nLes droits administrateur sont nécessaires pour la désinstaller.$\r$\n$\r$\nRelancer avec des privilèges élevés ?"

; ====================================================================
;  Installer functions
; ====================================================================

Function .onInit
    ; Language selection dialog
    !insertmacro MUI_LANGDLL_DISPLAY

    ; Architecture check (Windows 10+ and amd64/arm64)
    !insertmacro wails.checkArchitecture

    ; Check for /allusers flag (elevated relaunch)
    ${GetParameters} $0
    ClearErrors
    ${GetOptions} $0 "/allusers" $1
    ${IfNot} ${Errors}
        StrCpy $InstMode "allusers"
        SetShellVarContext all
        StrCpy $INSTDIR "$PROGRAMFILES64\${INFO_PRODUCTNAME}"
    ${Else}
        StrCpy $InstMode "user"
        SetShellVarContext current
        StrCpy $INSTDIR "$LOCALAPPDATA\${INFO_PRODUCTNAME}"
    ${EndIf}
FunctionEnd

; ---- Install Mode Selection Page ----

Function InstModeCreate
    ; Skip when relaunched in admin mode
    ${If} $InstMode == "allusers"
        Abort
    ${EndIf}

    nsDialogs::Create 1018
    Pop $0
    ${If} $0 == error
        Abort
    ${EndIf}

    !insertmacro MUI_HEADER_TEXT "$(scope_title)" "$(scope_subtitle)"

    ; Each choice says what it allows, not only what it costs: the Windows
    ; service is the difference that matters, and it is decided here.
    ${If} $BoldFont == ""
        CreateFont $BoldFont "$(^Font)" "$(^FontSize)" "700"
    ${EndIf}

    ${NSD_CreateRadioButton} 0u 0u 100% 12u "$(scope_user)"
    Pop $RadioUser
    SendMessage $RadioUser ${WM_SETFONT} $BoldFont 0
    ${NSD_Check} $RadioUser

    ${NSD_CreateLabel} 12u 13u 288u 32u "$(scope_user_desc)"
    Pop $0

    ${NSD_CreateRadioButton} 0u 50u 100% 12u "$(scope_admin)"
    Pop $RadioAdmin
    SendMessage $RadioAdmin ${WM_SETFONT} $BoldFont 0

    ${NSD_CreateLabel} 12u 63u 288u 32u "$(scope_admin_desc)"
    Pop $0

    ${NSD_CreateHLine} 0u 101u 100% 1u ""
    Pop $0

    ${NSD_CreateLabel} 0u 106u 100% 24u "$(scope_service)"
    Pop $0

    nsDialogs::Show
FunctionEnd

Function InstModeLeave
    ${NSD_GetState} $RadioAdmin $0
    ${If} $0 == ${BST_CHECKED}
        ; Relaunch with admin via UAC prompt
        ClearErrors
        ExecShell "runas" "$EXEPATH" "/allusers" SW_SHOWNORMAL
        ${If} ${Errors}
            ; UAC declined or unavailable: stay on this page rather than
            ; switching to a per-user install the user did not choose — it
            ; could never host the service.
            MessageBox MB_OK|MB_ICONINFORMATION "$(elevation_failed)"
            Abort
        ${EndIf}
        ; Elevated instance is running - close this one
        Quit
    ${EndIf}

    ; Per-user install
    StrCpy $InstMode "user"
    SetShellVarContext current
    StrCpy $INSTDIR "$LOCALAPPDATA\${INFO_PRODUCTNAME}"
FunctionEnd

; ---- Directory page ----

; Sets $0 to 1 when $INSTDIR is below DIR (a comparison that ignores case,
; like the file system).
!macro _InstDirUnder DIR
    StrLen $2 "${DIR}\"
    StrCpy $1 $INSTDIR $2
    ${If} $1 == "${DIR}\"
        StrCpy $0 1
    ${EndIf}
!macroend

; Sets $0 to 1 when $INSTDIR is inside Program Files, 0 otherwise. The
; service refuses to be installed from anywhere else (winsvc.CheckLocation):
; it runs this executable under a service account, so a folder ordinary users
; can write to would hand that account to them.
Function InstDirInProgramFiles
    StrCpy $0 0
    !insertmacro _InstDirUnder "$PROGRAMFILES64"
    !insertmacro _InstDirUnder "$PROGRAMFILES32"
FunctionEnd

; An all-users install exists to make the service possible; moving it out of
; Program Files would quietly rule the service out.
Function DirLeave
    ${If} $InstMode != "allusers"
        Return
    ${EndIf}
    Call InstDirInProgramFiles
    ${If} $0 == 0
        MessageBox MB_YESNO|MB_ICONEXCLAMATION "$(dir_no_service)" /SD IDYES IDYES keepDir
        Abort
        keepDir:
    ${EndIf}
FunctionEnd

; ---- Finish page ----

Function FinishPre
    ${If} $InstMode == "allusers"
        StrCpy $FinishText "$(finish_allusers)"
    ${Else}
        StrCpy $FinishText "$(finish_user)"
    ${EndIf}
FunctionEnd

; ---- Desktop shortcut callback (Finish page checkbox) ----

Function CreateDesktopShortcut
    ; Always create on the current user's desktop, even for all-users installs
    SetShellVarContext current
    CreateShortcut "$DESKTOP\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"
    ; Restore shell context
    ${If} $InstMode == "allusers"
        SetShellVarContext all
    ${EndIf}
FunctionEnd

; ====================================================================
;  Installer section
; ====================================================================

Section "${INFO_PRODUCTNAME}" SecMain
    SectionIn RO

    SetOutPath $INSTDIR

    ; Install WebView2 runtime if missing
    !insertmacro wails.webview2runtime

    ; A running service holds the executable open, and Windows refuses to
    ; replace a file in use. Only an all-users install can host the service.
    StrCpy $ServiceWasRunning "0"
    ${If} $InstMode == "allusers"
        nsExec::ExecToStack 'sc.exe query ${SERVICE_NAME}'
        Pop $0
        Pop $1
        ${If} $0 == 0
            ${StrStr} $2 $1 "RUNNING"
            ${If} $2 != ""
                StrCpy $ServiceWasRunning "1"
                DetailPrint "Stopping the SyslogStudio service for the update"
                nsExec::ExecToLog 'sc.exe stop ${SERVICE_NAME}'
                Pop $0
                StrCpy $3 0
                ${Do}
                    Sleep 500
                    nsExec::ExecToStack 'sc.exe query ${SERVICE_NAME}'
                    Pop $0
                    Pop $1
                    ${StrStr} $2 $1 "STOPPED"
                    ${If} $2 != ""
                        ${ExitDo}
                    ${EndIf}
                    IntOp $3 $3 + 1
                ${LoopUntil} $3 >= 60
            ${EndIf}
        ${EndIf}
    ${EndIf}

    ; Copy application binary
    SetOutPath $INSTDIR
    !insertmacro wails.files

    ; Start it again: an update must not leave the machine without the
    ; receiver it relies on. A service the administrator had stopped stays
    ; stopped.
    ${If} $ServiceWasRunning == "1"
        DetailPrint "Starting the SyslogStudio service again"
        nsExec::ExecToLog 'sc.exe start ${SERVICE_NAME}'
        Pop $0
    ${EndIf}

    ; File & protocol associations (no-op when none are defined in wails.json)
    !insertmacro wails.associateFiles
    !insertmacro wails.associateCustomProtocols

    ; ---- Start menu shortcuts ----
    CreateDirectory "$SMPROGRAMS\${INFO_PRODUCTNAME}"
    CreateShortcut "$SMPROGRAMS\${INFO_PRODUCTNAME}\${INFO_PRODUCTNAME}.lnk" \
        "$INSTDIR\${PRODUCT_EXECUTABLE}"
    CreateShortcut "$SMPROGRAMS\${INFO_PRODUCTNAME}\Uninstall ${INFO_PRODUCTNAME}.lnk" \
        "$INSTDIR\uninstall.exe"

    ; ---- Uninstaller ----
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; ---- Add / Remove Programs registry ----
    SetRegView 64
    ${If} $InstMode == "allusers"
        WriteRegStr   HKLM "${UNINST_KEY}" "Publisher"              "${INFO_COMPANYNAME}"
        WriteRegStr   HKLM "${UNINST_KEY}" "DisplayName"            "${INFO_PRODUCTNAME}"
        WriteRegStr   HKLM "${UNINST_KEY}" "DisplayVersion"         "${INFO_PRODUCTVERSION}"
        WriteRegStr   HKLM "${UNINST_KEY}" "DisplayIcon"            "$INSTDIR\${PRODUCT_EXECUTABLE}"
        WriteRegStr   HKLM "${UNINST_KEY}" "InstallLocation"        "$INSTDIR"
        WriteRegStr   HKLM "${UNINST_KEY}" "UninstallString"        '"$INSTDIR\uninstall.exe"'
        WriteRegStr   HKLM "${UNINST_KEY}" "QuietUninstallString"   '"$INSTDIR\uninstall.exe" /S'
        WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
        WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
        WriteRegStr   HKLM "${UNINST_KEY}" "InstallMode"            "allusers"
        ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
        IntFmt $0 "0x%08X" $0
        WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize"          "$0"
    ${Else}
        WriteRegStr   HKCU "${UNINST_KEY}" "Publisher"              "${INFO_COMPANYNAME}"
        WriteRegStr   HKCU "${UNINST_KEY}" "DisplayName"            "${INFO_PRODUCTNAME}"
        WriteRegStr   HKCU "${UNINST_KEY}" "DisplayVersion"         "${INFO_PRODUCTVERSION}"
        WriteRegStr   HKCU "${UNINST_KEY}" "DisplayIcon"            "$INSTDIR\${PRODUCT_EXECUTABLE}"
        WriteRegStr   HKCU "${UNINST_KEY}" "InstallLocation"        "$INSTDIR"
        WriteRegStr   HKCU "${UNINST_KEY}" "UninstallString"        '"$INSTDIR\uninstall.exe"'
        WriteRegStr   HKCU "${UNINST_KEY}" "QuietUninstallString"   '"$INSTDIR\uninstall.exe" /S'
        WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
        WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
        WriteRegStr   HKCU "${UNINST_KEY}" "InstallMode"            "user"
        ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
        IntFmt $0 "0x%08X" $0
        WriteRegDWORD HKCU "${UNINST_KEY}" "EstimatedSize"          "$0"
    ${EndIf}
SectionEnd

; ====================================================================
;  Uninstaller
; ====================================================================

Function un.onInit
    SetRegView 64

    ; Detect how the app was installed
    ReadRegStr $InstMode HKLM "${UNINST_KEY}" "InstallMode"
    ${If} $InstMode == "allusers"
        ; All-users install: need admin rights to uninstall
        UserInfo::GetAccountType
        Pop $0
        ${If} $0 != "Admin"
            MessageBox MB_YESNO|MB_ICONEXCLAMATION "$(un_need_admin)" IDYES elevate
            Abort
            elevate:
                ReadRegStr $1 HKLM "${UNINST_KEY}" "InstallLocation"
                ExecShell "runas" "$1\uninstall.exe"
                Quit
        ${EndIf}
        SetShellVarContext all
    ${Else}
        ; Per-user install
        StrCpy $InstMode "user"
        SetShellVarContext current
    ${EndIf}
FunctionEnd

Section "Uninstall"
    ; ---- Remove the service, while the executable that knows how is still
    ; here: it stops the service and removes it with its firewall rule and its
    ; event log source. Its data goes only if the user asks, below.
    ${If} $InstMode == "allusers"
        nsExec::ExecToStack 'sc.exe query ${SERVICE_NAME}'
        Pop $0
        Pop $1
        ${If} $0 == 0
            DetailPrint "Removing the SyslogStudio service"
            nsExec::ExecToLog '"$INSTDIR\${PRODUCT_EXECUTABLE}" service uninstall'
            Pop $0
        ${EndIf}
    ${EndIf}

    ; ---- Remove application files ----
    Delete "$INSTDIR\${PRODUCT_EXECUTABLE}"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"

    ; ---- Remove WebView2 data ----
    RMDir /r "$LOCALAPPDATA\SyslogStudio\WebView2"
    RMDir /r "$TEMP\SyslogStudio"

    ; ---- Remove shortcuts ----
    ; Desktop shortcut is always per-user
    SetShellVarContext current
    Delete "$DESKTOP\${INFO_PRODUCTNAME}.lnk"
    ; Restore context for start menu
    ${If} $InstMode == "allusers"
        SetShellVarContext all
    ${EndIf}
    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}\${INFO_PRODUCTNAME}.lnk"
    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}\Uninstall ${INFO_PRODUCTNAME}.lnk"
    RMDir "$SMPROGRAMS\${INFO_PRODUCTNAME}"

    ; ---- File & protocol associations ----
    !insertmacro wails.unassociateFiles
    !insertmacro wails.unassociateCustomProtocols

    ; ---- Remove registry entries ----
    SetRegView 64
    ${If} $InstMode == "allusers"
        DeleteRegKey HKLM "${UNINST_KEY}"
    ${Else}
        DeleteRegKey HKCU "${UNINST_KEY}"
    ${EndIf}

    ; ---- Optionally remove application data ----
    MessageBox MB_YESNO|MB_ICONQUESTION "$(remove_data)" IDYES removeData IDNO done
    removeData:
        ; Config and database in %AppData%\SyslogStudio
        RMDir /r "$AppData\SyslogStudio"
        ; And the service's, when this was an all-users install.
        ${If} $InstMode == "allusers"
            ReadEnvStr $0 PROGRAMDATA
            ${If} $0 != ""
                RMDir /r "$0\SyslogStudio"
            ${EndIf}
        ${EndIf}
    done:
SectionEnd
