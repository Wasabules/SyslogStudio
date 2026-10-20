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
##   - Over an existing install (the in-app update), updates that copy in
##     place, same mode and folder, instead of asking again
##   - Waits for running copies (tray, other sessions) and the service to
##     stop before replacing or removing the executable
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

; StrFunc functions must be declared once per side before use.
${StrStr}
${UnStrStr}

; The Windows service SyslogStudio can install (Settings > Background). It
; runs this very executable, so an update has to stop it to replace the file
; and start it again afterwards, and an uninstall has to remove it first.
!define SERVICE_NAME "SyslogStudio"
Var ServiceWasRunning

; The start-at-sign-in entry (internal/autostart's runKey and valueName).
!define AUTOSTART_KEY "Software\Microsoft\Windows\CurrentVersion\Run"
!define AUTOSTART_VALUE "SyslogStudio"

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
Var ExistingAll   ; install folder of an existing all-users copy, or ""
Var ExistingUser  ; install folder of an existing per-user copy, or ""
Var Relaunched    ; "1" in the elevated copy this installer starts

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
; The licence comes before the install mode: choosing all users relaunches
; this installer elevated, and the relaunch skips what was already seen.
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfRelaunched
!insertmacro MUI_PAGE_WELCOME
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfRelaunched
!insertmacro MUI_PAGE_LICENSE "..\..\..\LICENSE"
Page custom InstModeCreate InstModeLeave
!define MUI_PAGE_CUSTOMFUNCTION_PRE DirPre
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

LangString scope_both        ${LANG_ENGLISH} "${INFO_PRODUCTNAME} is installed both ways on this PC: each choice updates its own copy, where it is."
LangString scope_both        ${LANG_FRENCH}  "${INFO_PRODUCTNAME} est installé des deux façons sur ce PC : chaque choix met à jour sa propre copie, là où elle est."

LangString update_title      ${LANG_ENGLISH} "Update"
LangString update_title      ${LANG_FRENCH}  "Mise à jour"

LangString update_subtitle   ${LANG_ENGLISH} "${INFO_PRODUCTNAME} is installed for all users."
LangString update_subtitle   ${LANG_FRENCH}  "${INFO_PRODUCTNAME} est installé pour tous les utilisateurs."

LangString update_allusers   ${LANG_ENGLISH} "The installed copy, in $ExistingAll, will be updated where it is. Its Windows service, if it has one, is stopped for the update and started again.$\r$\n$\r$\nUpdating it takes administrator rights: Windows will ask for them when you click Next."
LangString update_allusers   ${LANG_FRENCH}  "La copie installée, dans $ExistingAll, sera mise à jour là où elle est. Son service Windows, s'il existe, est arrêté le temps de la mise à jour puis relancé.$\r$\n$\r$\nLa mise à jour demande les droits administrateur : Windows les demandera quand vous cliquerez sur Suivant."

LangString update_elevation_failed ${LANG_ENGLISH} "Administrator rights were not granted, so the copy installed for all users cannot be updated.$\r$\n$\r$\nClick Next to try again."
LangString update_elevation_failed ${LANG_FRENCH}  "Les droits administrateur n'ont pas été accordés : la copie installée pour tous les utilisateurs ne peut pas être mise à jour.$\r$\n$\r$\nCliquez sur Suivant pour réessayer."

LangString app_running       ${LANG_ENGLISH} "${INFO_PRODUCTNAME} is running, and Windows cannot update or remove a program in use.$\r$\n$\r$\nQuit it, including from its icon in the notification area (right-click > Quit) and in any other user's session where it is open, then click Retry."
LangString app_running       ${LANG_FRENCH}  "${INFO_PRODUCTNAME} est en cours d'exécution, et Windows ne peut ni mettre à jour ni supprimer un programme en cours d'utilisation.$\r$\n$\r$\nQuittez-le, y compris depuis son icône dans la zone de notification (clic droit › Quitter) et dans la session de tout autre utilisateur où il est ouvert, puis cliquez sur Recommencer."

LangString app_still_running ${LANG_ENGLISH} "Cancelled: ${INFO_PRODUCTNAME} is still running."
LangString app_still_running ${LANG_FRENCH}  "Annulé : ${INFO_PRODUCTNAME} est toujours en cours d'exécution."

LangString remove_data       ${LANG_ENGLISH} "Do you also want to remove application data (settings, log database)?"
LangString remove_data       ${LANG_FRENCH}  "Voulez-vous aussi supprimer les données de l'application (paramètres, base de logs) ?"

LangString un_need_admin     ${LANG_ENGLISH} "This application was installed for all users.$\r$\nAdministrator rights are needed to uninstall.$\r$\n$\r$\nRestart with elevated privileges?"
LangString un_need_admin     ${LANG_FRENCH}  "Cette application a été installée pour tous les utilisateurs.$\r$\nLes droits administrateur sont nécessaires pour la désinstaller.$\r$\n$\r$\nRelancer avec des privilèges élevés ?"

; ====================================================================
;  Installer functions
; ====================================================================

Function .onInit
    ${GetParameters} $0

    ; The elevated copy this installer relaunches already has the language,
    ; and the welcome and licence pages behind it.
    ClearErrors
    ${GetOptions} $0 "/relaunched" $1
    ${IfNot} ${Errors}
        StrCpy $Relaunched "1"
    ${EndIf}
    ClearErrors
    ${GetOptions} $0 "/lang=" $1
    ${If} ${Errors}
        !insertmacro MUI_LANGDLL_DISPLAY
    ${Else}
        StrCpy $LANGUAGE $1
    ${EndIf}

    ; Architecture check (Windows 10+ and amd64/arm64)
    !insertmacro wails.checkArchitecture

    ; What is installed already. Installing in a mode that has a copy updates
    ; that copy where it is: a second copy beside it would leave the service,
    ; the shortcuts and the uninstaller on the old one.
    SetRegView 64
    ReadRegStr $ExistingAll HKLM "${UNINST_KEY}" "InstallLocation"
    ReadRegStr $ExistingUser HKCU "${UNINST_KEY}" "InstallLocation"

    ; /allusers: the elevated relaunch, or a silent all-users install
    ClearErrors
    ${GetOptions} $0 "/allusers" $1
    ${IfNot} ${Errors}
        StrCpy $InstMode "allusers"
        SetShellVarContext all
        ${If} $ExistingAll != ""
            StrCpy $INSTDIR $ExistingAll
        ${Else}
            StrCpy $INSTDIR "$PROGRAMFILES64\${INFO_PRODUCTNAME}"
        ${EndIf}
    ${Else}
        Call UseUserMode
    ${EndIf}
FunctionEnd

; Per-user mode, in the existing per-user copy's folder when there is one.
Function UseUserMode
    StrCpy $InstMode "user"
    SetShellVarContext current
    ${If} $ExistingUser != ""
        StrCpy $INSTDIR $ExistingUser
    ${Else}
        StrCpy $INSTDIR "$LOCALAPPDATA\${INFO_PRODUCTNAME}"
    ${EndIf}
FunctionEnd

; Sets $0 to 1 when the chosen mode already has a copy, which this updates.
Function IsUpdate
    StrCpy $0 0
    ${If} $InstMode == "allusers"
        ${If} $ExistingAll != ""
            StrCpy $0 1
        ${EndIf}
    ${ElseIf} $ExistingUser != ""
        StrCpy $0 1
    ${EndIf}
FunctionEnd

; Welcome and licence: shown once, not again by the elevated relaunch.
Function SkipIfRelaunched
    ${If} $Relaunched == "1"
        Abort
    ${EndIf}
FunctionEnd

; ---- Install Mode Selection Page ----

; Skipped when the mode is already settled: by the elevated relaunch, or by
; an update of the only copy there is when it is a per-user one. Updating
; the only copy when it is an all-users one shows a notice instead: Windows
; is about to ask for administrator rights, and this says why.
Function InstModeCreate
    ${If} $InstMode == "allusers"
        Abort
    ${EndIf}
    ${If} $ExistingUser != ""
    ${AndIf} $ExistingAll == ""
        Abort
    ${EndIf}

    nsDialogs::Create 1018
    Pop $0
    ${If} $0 == error
        Abort
    ${EndIf}

    ${If} $ExistingAll != ""
    ${AndIf} $ExistingUser == ""
        !insertmacro MUI_HEADER_TEXT "$(update_title)" "$(update_subtitle)"
        ${NSD_CreateLabel} 0u 0u 100% 100u "$(update_allusers)"
        Pop $0
        nsDialogs::Show
        Return
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

    ; Both installed: say that each choice updates its own copy.
    ${If} $ExistingAll != ""
        ${NSD_CreateLabel} 0u 106u 100% 24u "$(scope_both)"
    ${Else}
        ${NSD_CreateLabel} 0u 106u 100% 24u "$(scope_service)"
    ${EndIf}
    Pop $0

    nsDialogs::Show
FunctionEnd

Function InstModeLeave
    ${If} $ExistingAll != ""
    ${AndIf} $ExistingUser == ""
        ; The update notice: only the all-users copy to update
        StrCpy $0 ${BST_CHECKED}
        StrCpy $1 "$(update_elevation_failed)"
    ${Else}
        ${NSD_GetState} $RadioAdmin $0
        StrCpy $1 "$(elevation_failed)"
    ${EndIf}
    ${If} $0 == ${BST_CHECKED}
        ; Relaunch with admin via UAC prompt
        ClearErrors
        ExecShell "runas" "$EXEPATH" "/allusers /relaunched /lang=$LANGUAGE" SW_SHOWNORMAL
        ${If} ${Errors}
            ; UAC declined or unavailable: stay on this page rather than
            ; switching to a per-user install the user did not choose — it
            ; could never host the service.
            MessageBox MB_OK|MB_ICONINFORMATION $1
            Abort
        ${EndIf}
        ; Elevated instance is running - close this one
        Quit
    ${EndIf}

    Call UseUserMode
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

; An update keeps the folder of the copy it updates.
Function DirPre
    Call IsUpdate
    ${If} $0 == 1
        Abort
    ${EndIf}
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

; ---- The service, and copies of the application still running ----

; ${StrStr} on the installer's side, ${UnStrStr} on the uninstaller's.
!macro _StrStrFor UN OUT HAYSTACK NEEDLE
    !if "${UN}" == ""
        ${StrStr} ${OUT} ${HAYSTACK} "${NEEDLE}"
    !else
        ${UnStrStr} ${OUT} ${HAYSTACK} "${NEEDLE}"
    !endif
!macroend

; Both the installer and the uninstaller need these, under their own prefix.
!macro DefineRunningChecks UN

; Stops the service when it is running and waits for it to stop (30 s at
; most), recording in $ServiceWasRunning whether it was. Only an all-users
; install can host it.
Function ${UN}StopService
    StrCpy $ServiceWasRunning "0"
    ${If} $InstMode != "allusers"
        Return
    ${EndIf}
    nsExec::ExecToStack 'sc.exe query ${SERVICE_NAME}'
    Pop $0
    Pop $1
    ${If} $0 != 0
        Return
    ${EndIf}
    !insertmacro _StrStrFor "${UN}" $2 $1 "RUNNING"
    ${If} $2 == ""
        Return
    ${EndIf}
    StrCpy $ServiceWasRunning "1"
    DetailPrint "Stopping the SyslogStudio service"
    nsExec::ExecToLog 'sc.exe stop ${SERVICE_NAME}'
    Pop $0
    StrCpy $3 0
    ${Do}
        Sleep 500
        nsExec::ExecToStack 'sc.exe query ${SERVICE_NAME}'
        Pop $0
        Pop $1
        !insertmacro _StrStrFor "${UN}" $2 $1 "STOPPED"
        ${If} $2 != ""
            ${ExitDo}
        ${EndIf}
        IntOp $3 $3 + 1
    ${LoopUntil} $3 >= 60
FunctionEnd

; Starts the service again if StopService stopped it: an update must not
; leave the machine without the receiver it relies on. A service the
; administrator had stopped stays stopped.
Function ${UN}RestartService
    ${If} $ServiceWasRunning == "1"
        DetailPrint "Starting the SyslogStudio service again"
        nsExec::ExecToLog 'sc.exe start ${SERVICE_NAME}'
        Pop $0
    ${EndIf}
FunctionEnd

; Waits until nothing runs $INSTDIR\${PRODUCT_EXECUTABLE}. Windows neither
; replaces nor deletes a running executable, and the copy running may be
; hidden in the notification area, or in another user's session. Opening the
; file for writing is the test: it fails exactly while some process runs the
; file, whoever and wherever, and a copy elsewhere does not count. A few quiet
; retries first let a copy that is already quitting finish — the one that
; just launched this update. Sets $0 to "ok", or "cancel" when the user gives
; up.
Function ${UN}WaitForAppClosed
    StrCpy $0 "ok"
    ${IfNot} ${FileExists} "$INSTDIR\${PRODUCT_EXECUTABLE}"
        Return
    ${EndIf}
    StrCpy $2 0
    ${Do}
        ClearErrors
        FileOpen $1 "$INSTDIR\${PRODUCT_EXECUTABLE}" a
        ${IfNot} ${Errors}
            FileClose $1
            ${ExitDo}
        ${EndIf}
        IntOp $2 $2 + 1
        ${If} $2 < 10
            Sleep 500
            ${Continue}
        ${EndIf}
        MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(app_running)" /SD IDCANCEL IDRETRY retry
        StrCpy $0 "cancel"
        ${ExitDo}
        retry:
    ${Loop}
FunctionEnd

!macroend

!insertmacro DefineRunningChecks ""
!insertmacro DefineRunningChecks "un."

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

    ; Whatever runs the executable keeps Windows from replacing it: the
    ; service, and any copy of the application. Cancelling changes nothing.
    Call StopService
    Call WaitForAppClosed
    ${If} $0 == "cancel"
        Call RestartService
        Abort "$(app_still_running)"
    ${EndIf}

    ; Copy application binary
    SetOutPath $INSTDIR
    !insertmacro wails.files

    Call RestartService

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

    ; Detect how the app was installed: all-users only when the all-users
    ; entry is this very copy. A per-user copy can sit beside an all-users
    ; one, and uninstalling it must not take the other's entry, or its
    ; service, with it.
    ReadRegStr $InstMode HKLM "${UNINST_KEY}" "InstallMode"
    ReadRegStr $0 HKLM "${UNINST_KEY}" "InstallLocation"
    ${If} $0 != $INSTDIR
        StrCpy $InstMode "user"
    ${EndIf}
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
    ; ---- Nothing may still run the executable, or it could not be deleted.
    ; Cancelling leaves everything as it was, the service included.
    Call un.StopService
    Call un.WaitForAppClosed
    ${If} $0 == "cancel"
        Call un.RestartService
        Abort "$(app_still_running)"
    ${EndIf}

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

    ; ---- Remove WebView2 data ----
    ; The user's own whatever the install mode: in the all-users context,
    ; $LOCALAPPDATA is ProgramData. It goes before the application files
    ; because a per-user install shares %LOCALAPPDATA%\SyslogStudio, which
    ; RMDir below removes only once it is empty.
    SetShellVarContext current
    RMDir /r "$LOCALAPPDATA\SyslogStudio\WebView2"
    RMDir /r "$TEMP\SyslogStudio"

    ; ---- Remove application files ----
    Delete "$INSTDIR\${PRODUCT_EXECUTABLE}"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"

    ; ---- Remove shortcuts ----
    ; Desktop shortcut is always per-user (the context is still current)
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

    ; ---- Start at sign-in (Settings > Background) ----
    ; The current user's entry, when it starts this copy: left behind, it
    ; would run a file that no longer exists at every sign-in. Other users'
    ; entries are out of reach and fail the same harmless way.
    ReadRegStr $0 HKCU "${AUTOSTART_KEY}" "${AUTOSTART_VALUE}"
    StrCpy $1 '"$INSTDIR\${PRODUCT_EXECUTABLE}"'
    StrLen $2 $1
    StrCpy $3 $0 $2
    ${If} $3 == $1
        DeleteRegValue HKCU "${AUTOSTART_KEY}" "${AUTOSTART_VALUE}"
    ${EndIf}

    ; ---- Optionally remove application data ----
    MessageBox MB_YESNO|MB_ICONQUESTION "$(remove_data)" IDYES removeData IDNO done
    removeData:
        ; Config and database in the user's own %AppData%\SyslogStudio: in
        ; the all-users context set for the start menu, $AppData would be
        ; ProgramData.
        SetShellVarContext current
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
