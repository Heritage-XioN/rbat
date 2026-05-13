/*
 * API Hooking and Instrumentation Detection
 * Detects common APIs, strings, and patterns used for API hooking, 
 * code injection, and binary instrumentation.
 * Supports Windows, Linux, and macOS.
 */

rule Windows_Hooking_APIs {
    meta:
        description = "Windows API hooking and event monitoring"
        author = "rBAT Project"
        severity = "Medium"

    strings:
        /* Standard Hooking APIs */
        $api_sethook = "SetWindowsHookEx" ascii wide
        $api_unhook = "UnhookWindowsHookEx" ascii wide
        $api_callnext = "CallNextHookEx" ascii wide
        
        /* Event Hooking */
        $api_setwinevent = "SetWinEventHook" ascii wide
        $api_unhookwinevent = "UnhookWinEventHook" ascii wide

        /* Memory manipulation for hooking */
        $api_virtprot = "VirtualProtect" ascii wide
        $api_virtprotex = "VirtualProtectEx" ascii wide
        $api_writeproc = "WriteProcessMemory" ascii wide
        $api_flushinstr = "FlushInstructionCache" ascii wide

    condition:
        any of them
}

rule Linux_Hooking_APIs {
    meta:
        description = "Linux API hooking and process manipulation"
        author = "rBAT Project"
        severity = "Medium"

    strings:
        /* Process control */
        $api_ptrace = "ptrace" ascii
        
        /* Memory protection */
        $api_mprotect = "mprotect" ascii
        
        /* Dynamic loading hooks */
        $api_dlopen = "dlopen" ascii
        $api_dlsym = "dlsym" ascii
        
        /* Environment variables often used for hooking */
        $env_preload = "LD_PRELOAD" ascii
        $env_audit = "LD_AUDIT" ascii

    condition:
        any of them
}

rule MacOS_Hooking_APIs {
    meta:
        description = "macOS API hooking and Mach task manipulation"
        author = "rBAT Project"
        severity = "Medium"

    strings:
        /* Mach VM operations */
        $api_vmprot = "vm_protect" ascii
        $api_vmwrite = "vm_write" ascii
        $api_machvmprot = "mach_vm_protect" ascii
        $api_machvmwrite = "mach_vm_write" ascii
        
        /* Task and Thread manipulation */
        $api_taskforpid = "task_for_pid" ascii
        $api_threadcreate = "thread_create_running" ascii
        
        /* Dynamic loading */
        $api_nsobject = "NSCreateObjectFileImageFromMemory" ascii

    condition:
        any of them
}

rule Hooking_Framework_Indicators {
    meta:
        description = "Indicators of common hooking and instrumentation frameworks"
        author = "rBAT Project"
        severity = "High"

    strings:
        /* Microsoft Detours */
        $detours_sig = "Detours" ascii wide
        $detours_api = "DetourTransactionBegin" ascii wide
        $detours_api2 = "DetourUpdateThread" ascii wide
        $detours_api3 = "DetourAttach" ascii wide
        
        /* MinHook */
        $minhook_sig = "MinHook" ascii wide
        $minhook_api = "MH_Initialize" ascii wide
        $minhook_api2 = "MH_CreateHook" ascii wide
        
        /* Frida */
        $frida_sig = "frida-agent" ascii wide
        $frida_sig2 = "gum-js" ascii wide
        
        /* EasyHook */
        $easyhook_sig = "EasyHook" ascii wide
        
        /* Generic Hooking strings */
        $gen_hook = "hook_function" ascii wide nocase
        $gen_unhook = "unhook_function" ascii wide nocase
        $gen_trampoline = "trampoline" ascii wide nocase

    condition:
        any of them
}
