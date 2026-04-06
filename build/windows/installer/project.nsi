Unicode true

####
## SyslogStudio Installer
##
## Features:
##   - Dual install mode: per-user (no admin) or all-users (admin via UAC)
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

; ====================================================================
;  Pages
; ====================================================================
!insertmacro MUI_PAGE_WELCOME
Page custom InstModeCreate InstModeLeave
!insertmacro MUI_PAGE_LICENSE "..\..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
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

LangString scope_subtitle    ${LANG_ENGLISH} "Choose how to install ${INFO_PRODUCTNAME}."
LangString scope_subtitle    ${LANG_FRENCH}  "Choisissez comment installer ${INFO_PRODUCTNAME}."

LangString scope_group       ${LANG_ENGLISH} "Installation Scope"
LangString scope_group       ${LANG_FRENCH}  "Portée de l'installation"

LangString scope_user        ${LANG_ENGLISH} "Install just for me"
LangString scope_user        ${LANG_FRENCH}  "Installer uniquement pour moi"

LangString scope_user_desc   ${LANG_ENGLISH} "No administrator rights required."
LangString scope_user_desc   ${LANG_FRENCH}  "Aucun droit administrateur requis."

LangString scope_admin       ${LANG_ENGLISH} "Install for all users"
LangString scope_admin       ${LANG_FRENCH}  "Installer pour tous les utilisateurs"

LangString scope_admin_desc  ${LANG_ENGLISH} "Requires administrator rights."
LangString scope_admin_desc  ${LANG_FRENCH}  "Nécessite des droits administrateur."

LangString launch_app        ${LANG_ENGLISH} "Launch ${INFO_PRODUCTNAME}"
LangString launch_app        ${LANG_FRENCH}  "Lancer ${INFO_PRODUCTNAME}"

LangString desktop_shortcut  ${LANG_ENGLISH} "Create desktop shortcut"
LangString desktop_shortcut  ${LANG_FRENCH}  "Créer un raccourci sur le bureau"

LangString elevation_failed  ${LANG_ENGLISH} "Could not obtain administrator rights.$\r$\nThe application will be installed for the current user only."
LangString elevation_failed  ${LANG_FRENCH}  "Impossible d'obtenir les droits administrateur.$\r$\nL'application sera installée pour l'utilisateur courant uniquement."

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

    ${NSD_CreateGroupBox} 5u 5u 290u 105u "$(scope_group)"
    Pop $0

    ${NSD_CreateRadioButton} 20u 28u 260u 15u "$(scope_user)"
    Pop $RadioUser
    ${NSD_Check} $RadioUser

    ${NSD_CreateLabel} 35u 46u 250u 10u "$(scope_user_desc)"
    Pop $0

    ${NSD_CreateRadioButton} 20u 68u 260u 15u "$(scope_admin)"
    Pop $RadioAdmin

    ${NSD_CreateLabel} 35u 86u 250u 10u "$(scope_admin_desc)"
    Pop $0

    nsDialogs::Show
FunctionEnd

Function InstModeLeave
    ${NSD_GetState} $RadioAdmin $0
    ${If} $0 == ${BST_CHECKED}
        ; Relaunch with admin via UAC prompt
        ExecShell "runas" "$EXEPATH" "/allusers" SW_SHOWNORMAL
        ${If} ${Errors}
            ; UAC denied or unavailable - fall back to user install
            MessageBox MB_OK|MB_ICONINFORMATION "$(elevation_failed)"
            StrCpy $InstMode "user"
            SetShellVarContext current
            StrCpy $INSTDIR "$LOCALAPPDATA\${INFO_PRODUCTNAME}"
            Return
        ${EndIf}
        ; Elevated instance is running - close this one
        Quit
    ${EndIf}

    ; Per-user install
    StrCpy $InstMode "user"
    SetShellVarContext current
    StrCpy $INSTDIR "$LOCALAPPDATA\${INFO_PRODUCTNAME}"
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

    ; Copy application binary
    SetOutPath $INSTDIR
    !insertmacro wails.files

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
    ; ---- Remove application files ----
    Delete "$INSTDIR\${PRODUCT_EXECUTABLE}"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"

    ; ---- Remove WebView2 data ----
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
    done:
SectionEnd
