/*
 * Suspicious Strings YARA Rules
 * Detects C2 frameworks, suspicious APIs, file paths, credentials, and obfuscation patterns
 * Supports PE, ELF, and Mach-O binaries
 * Based on industry standards and threat intelligence
 */

rule C2_Framework_Indicators {
    meta:
        description = "Command and Control framework indicators"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        /* Cobalt Strike patterns */
        $cobalt_artifact = "artifact.exe" ascii wide nocase
        $cobalt_powershell = "Invoke-Mimikatz" ascii wide nocase
        $cobalt_pscmd = "powershell -enc" ascii wide nocase

        /* Havoc C2 patterns */
        $havoc_dll = "Havoc" ascii wide nocase

        /* Brute Ratel patterns */
        $brute_ratel = "BruteRAT" ascii wide nocase
        $brute_java = "bruteratel" ascii wide nocase

        /* Quasar RAT patterns */
        $quasar = "Quasar" ascii wide nocase
        $quasar_client = "QuasarClient" ascii wide nocase

        /* Async RAT patterns */
        $asyncrat = "AsyncRAT" ascii wide nocase
        $async_remote = "AsyncShell" ascii wide nocase

        /* Remcos RAT patterns */
        $remcos = "Remcos" ascii wide nocase
        $remcos_pro = "RemcosPro" ascii wide nocase

        /* Vidar patterns */
        $vidar = "Vidar" ascii wide nocase

    condition:
        any of them
}

rule Network_Indicators {
    meta:
        description = "Network indicators - URLs, IPs, and domains"
        author = "rBAT Project"
        version = "0.2.1"

    strings:
        /* IP addresses in URLs */
        $url_ip = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase

        /* Dark web/TOR domains */
        $tor_domain = /\.onion/ nocase

        /* Common C2 ports/patterns */
        $c2_port_4444 = ":4444" ascii
        $c2_port_5555 = ":5555" ascii
        $c2_port_6666 = ":6666" ascii

    condition:
        $url_ip or $tor_domain or any of ($c2_port_*)
}

rule Windows_Suspicious_APIs {
    meta:
        description = "Windows malicious API patterns"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        /* Registry manipulation for persistence / malware */
        $api_regset = "RegSetValueA" ascii wide
        $api_regcreate = "RegCreateKeyA" ascii wide

        /* Service manipulation */
        $api_svc = "CreateServiceA" ascii wide
        $api_svcw = "CreateServiceW" ascii wide

        /* Network operations */
        $api_urlget = "URLDownloadToFileA" ascii wide

        /* Cryptography / Hashing */
        $api_crypt = "CryptHashMessageBlob" ascii wide

        /* Anti-analysis */
        $api_checkvm = "CheckRemoteDebuggerPresent" ascii wide

    condition:
        any of them
}

rule ELF_Suspicious_APIs {
    meta:
        description = "Linux/ELF suspicious system calls and functions (Low Confidence)"
        author = "rBAT Project"
        version = "0.2.1"

    strings:
        /* Process manipulation */
        $elf_ptrace = "ptrace" ascii
        $elf_ptrace_plt = "ptrace@plt" ascii

        /* Process execution */
        $elf_execve = "execve" ascii
        $elf_execve_plt = "execve@plt" ascii

    condition:
        any of them
}

rule MachO_Suspicious_APIs {
    meta:
        description = "macOS/Mach-O suspicious APIs"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        /* Dynamic library loading */
        $mac_nsload = "NSLinkModule" ascii

        /* Process manipulation */
        $mac_taskforp = "task_for_pid" ascii
        $mac_taskalloc = "task_alloc" ascii

        /* Inter-process communication */
        $mac_machport = "mach_port_allocate" ascii

        /* Hidden execution */
        $mac_hidden = "setuidroot" ascii
        $mac_rootpipe = "AuthorizationExecuteWithPrivileges"

        /* AppleScript execution */
        $mac_apples = "NSAppleScript" ascii
        $mac_osascript = "osascript" ascii

    condition:
        any of them
}

rule File_Paths_Malicious {
    meta:
        description = "Malicious file paths and locations"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        /* Windows paths */
        $path_win_system = /[a-zA-Z]:\\Windows\\(System32|SysWOW64)\\/ nocase
        $path_win_temp = /[a-zA-Z]:\\TEMP\\/ nocase
        $path_win_appdata = /[a-zA-Z]:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\Roaming\\/ nocase

        /* Unix/Linux paths */
        $path_unix_tmp = "/tmp/" ascii
        $path_unix_vartmp = "/var/tmp/" ascii
        $path_unix_devshm = "/dev/shm/" ascii

        /* Hidden files/directories (Unix) */
        $path_ssh = "/.ssh/" ascii
        $path_bashrc = "/.bashrc" ascii
        $path_profile = "/.profile" ascii
        $path_xauth = "/.Xauthority" ascii

    condition:
        any of them
}

rule Credential_Patterns {
    meta:
        description = "Hardcoded credentials and authentication tokens"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        /* Generic password patterns */
        $cred_pass = /password\s*[=:]\s*[a-zA-Z0-9@#\$\%\^\&\*\-\_]+/ nocase
        $cred_pwd = /pwd\s*[=:]\s*[a-zA-Z0-9@#\$\%\^\&\*\-\_]+/ nocase
        $cred_passwd = /passwd\s*[=:]\s*[a-zA-Z0-9@#\$\%\^\&\*\-\_]+/ nocase

        /* Username patterns */
        $cred_user = /user[name]?\s*[=:]\s*[a-zA-Z0-9@#\$\%\^\&\*\-\_]+/ nocase
        $cred_username = /username\s*[=:]\s*[a-zA-Z0-9@#\$\%\^\&\*\-\_]+/ nocase

        /* Database credentials */
        $cred_db_user = /(db|database)[_-]?(user|username)\s*[=:]/ nocase
        $cred_db_pass = /(db|database)[_-]?(pass|password)\s*[=:]/ nocase

        /* Authentication header */
        $cred_auth = "Authorization:" ascii wide

    condition:
        any of them
}

rule Email_Addresses {
    meta:
        description = "Email addresses - potential contact or C2 email"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ nocase

    condition:
        any of them
}

rule Obfuscation_Patterns {
    meta:
        description = "Obfuscation and encoding patterns"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        /* Base64 patterns (common in encoded payloads) */
        $b64_strict = /[A-Za-z0-9+\/]+=*$/ nocase

        /* XOR-related strings */
        $xor_encrypt = "XOREncrypt" ascii wide

    condition:
        any of them
}

rule Anti_Analysis_Techniques {
    meta:
        description = "Anti-debugging and anti-VM techniques"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        /* Windows anti-debug */
        $anti_debug = "CheckRemoteDebuggerPresent" ascii wide
        $anti_debug2 = "IsDebuggerPresent" ascii wide
        $anti_ntdbg = "NtQueryInformationProcess" ascii wide
        $anti_vm = "NtQueryVirtualMemory" ascii wide

        /* macOS anti-VM */
        $mac_vmware = "VMware" ascii wide
        $mac_parallels = "Parallels" ascii wide
        $mac_vbox = "VirtualBox" ascii wide

        /* Linux anti-VM */
        $linux_vmware = "vmware" ascii
        $linux_vbox = "VBox" ascii
        $linux_qemu = "QEMU" ascii
        $linux_xen = "Xen" ascii

        /* VM detection files */
        $vm_files = /\/sys\/class\/dmi\/id\// ascii
        $vm_proc = "/proc/xen/" ascii

    condition:
        any of them
}

rule Persistence_Mechanisms {
    meta:
        description = "Persistence mechanism indicators"
        author = "rBAT Project"
        version = "0.2.0"

    strings:
        /* Windows persistence */
        $persist_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $persist_schtask = "schtasks" ascii wide
        $persist_svc = "CreateService" ascii wide
        $persist_wmi = "IWbem" ascii wide
        $persistautorun = "AppInit_DLLs" ascii wide

        /* Unix persistence */
        $persist_cron = "crontab" ascii
        $persist_systemd = "systemd" ascii
        $persist_initd = "init.d" ascii
        $persist_rc = "rc.local" ascii
        $persist_profile = ".profile" ascii
        $persist_bashrc = ".bashrc" ascii

        /* Launch agents (macOS) */
        $mac_launch = "LaunchAgent" ascii
        $mac_plist = ".plist" ascii

        /* SSH authorized keys */
        $ssh_authkeys = "authorized_keys" ascii

    condition:
        any of them
}