rule Suspicious_Indicators {
    meta:
        description = "Detects interesting strings, C2 domains, APIs, and credentials in binaries"
        author = "rBAT Project"
        version = "0.1.0"

    strings:
        // URLs and Domains (Command and Control infrastructure)
        // find http/https and standard domain structures
        $url_http = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/ nocase
        $url_ip = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase

        // Suspicious Windows API Names
        // 'ascii wide' tells YARA to look for both standard ASCII and UTF-16 strings (common in Windows)
        $api_exec = "WinExec" ascii wide
        $api_shell = "ShellExecuteA" ascii wide
        $api_mem = "VirtualAlloc" ascii wide
        $api_lib = "LoadLibraryA" ascii wide
        $api_proc = "GetProcAddress" ascii wide
        $api_net = "InternetOpenUrlA" ascii wide

        // File Paths (Windows and Unix)
        // Looks for C:\... or /tmp/... style paths
        $path_win = /[a-zA-Z]:\\[a-zA-Z0-9\_\-\\]+\.[a-zA-Z0-9]+/ nocase
        $path_unix = /\/(bin|etc|tmp|var|usr)\/[a-zA-Z0-9\_\-\/]+/ nocase

        // Email Addresses
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ nocase

        // Hardcoded Credentials (Heuristics)
        $cred_pass = /password\s*=\s*[a-zA-Z0-9@#\$\%\^\&\*\-\_]+/ nocase
        $cred_admin = /admin\s*:\s*[a-zA-Z0-9@#\$\%\^\&\*\-\_]+/ nocase
        $cred_bearer = /Bearer\s+[a-zA-Z0-9\-\.\_]+/ nocase

    condition:
       // and return the exact string matches and their byte offsets.
        any of them
}