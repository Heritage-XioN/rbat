/*
 * Packer Signatures YARA Rules
 * Based on industry standards from Yara-Rules, MalwareLu, GoDaddy, DFIRnotes
 * Detection methods: Section names, entry point patterns, file content strings
 */

rule UPX_Packer_Section {
    meta:
        description = "UPX packed file - by section name"
        author = "rBAT Project"
        packer = "UPX"
        weight = 85

    strings:
        $section_upx0 = ".upx0" nocase
        $section_upx1 = ".upx1" nocase
        $section_upx2 = ".upx2" nocase
        $str_upx0 = "UPX0" ascii
        $str_upx1 = "UPX1" ascii
        $str_upx2 = "UPX2" ascii
        $str_upx_sig = "UPX!" ascii

    condition:
        any of ($section_*) or any of ($str_*)
}

rule UPX_Packer_EP {
    meta:
        description = "UPX packed file - by entry point pattern"
        author = "rBAT Project"
        packer = "UPX"
        weight = 90

    strings:
        $upx_ep_1 = { 6A 60 68 60 02 4B 00 E8 8B 04 00 00 83 65 FC 00 8D 45 90 50 FF 15 }
        $upx_ep_2 = { 60 BE 00 10 00 00 8D BE 00 10 FF FF 57 8B 5D FC 81 }
        $upx_ep_3 = { 60 BE 00 10 40 00 8D BE 00 10 FF FF 57 8B 5D FC 81 }

    condition:
        any of them
}

rule ASPack_Packer_Section {
    meta:
        description = "ASPack packed file - by section name"
        author = "rBAT Project"
        packer = "ASPack"
        weight = 90

    strings:
        $section_aspack = ".aspack" ascii wide
        $section_adata = ".adata" ascii wide
        $str_aspack = "ASPack" ascii wide
        $str_daStub = "DAStub" ascii wide

    condition:
        any of them
}

rule ASPack_Packer_EP {
    meta:
        description = "ASPack packed file - by entry point pattern"
        author = "rBAT Project"
        packer = "ASPack"
        weight = 85

    strings:
        $aspack_ep = { B8 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 80 8B 45 08 50 }

    condition:
        any of them
}

rule PECompact_Packer_Section {
    meta:
        description = "PECompact packed file - by section name"
        author = "rBAT Project"
        packer = "PECompact"
        weight = 85

    strings:
        $section_pec = ".pec" ascii nocase
        $section_pec2 = ".pec2" ascii nocase
        $str_pec = "PECompact" ascii
        $str_pec2 = "PECompact2" ascii

    condition:
        any of them
}

rule PECompact_Packer_EP {
    meta:
        description = "PECompact packed file - by entry point pattern"
        author = "rBAT Project"
        packer = "PECompact"
        weight = 90

    strings:
        $pec_ep_1 = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }
        $pec_ep_2 = { B8 00 00 00 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }
        $pec_ep_3 = { B8 00 00 00 00 80 B8 BF 10 00 10 01 74 7A }

    condition:
        any of them
}

rule Themida_Packer_Section {
    meta:
        description = "Themida packed file - by section name"
        author = "rBAT Project"
        packer = "Themida"
        weight = 90

    strings:
        $section_themida = ".themida" ascii nocase
        $str_themida = "Themida" ascii wide
        $str_secureengine = "SecureEngine" ascii wide
        $str_winlicen = "WinLicen" ascii wide

    condition:
        any of them
}

rule Themida_Packer_EP {
    meta:
        description = "Themida packed file - by entry point pattern"
        author = "rBAT Project"
        packer = "Themida"
        weight = 80

    strings:
        $themida_ep = { 60 E8 03 00 00 00 61 83 C4 10 89 45 }

    condition:
        any of them
}

rule VMProtect_Packer_Section {
    meta:
        description = "VMProtect packed file - by section name"
        author = "rBAT Project"
        packer = "VMProtect"
        weight = 85

    strings:
        $section_vmp0 = ".vmp0" ascii nocase
        $section_vmp1 = ".vmp1" ascii nocase
        $section_vmp2 = ".vmp2" ascii nocase
        $str_vprotect = "VProtect" ascii wide

    condition:
        any of them
}

rule Petite_Packer_Section {
    meta:
        description = "Petite packed file - by section name"
        author = "rBAT Project"
        packer = "Petite"
        weight = 85

    strings:
        $section_petite = ".petite" ascii nocase
        $str_petite = "Petite" ascii wide

    condition:
        any of them
}

rule FSG_Packer_Section {
    meta:
        description = "FSG packed file - by section name"
        author = "rBAT Project"
        packer = "FSG"
        weight = 85

    strings:
        $section_fsg = ".fsg" ascii nocase
        $str_fsg = "FSG" ascii wide
        $str_fsg_sig = "FSG!" ascii

    condition:
        any of them
}

rule FSG_Packer_EP {
    meta:
        description = "FSG packed file - by entry point pattern"
        author = "rBAT Project"
        packer = "FSG"
        weight = 85

    strings:
        $fsg_ep = { 55 8B EC 83 EC ?? 53 56 57 8B 5D 08 8B }

    condition:
        any of them
}

rule MEW_Packer_Section {
    meta:
        description = "MEW packed file - by section name"
        author = "rBAT Project"
        packer = "MEW"
        weight = 85

    strings:
        $section_mew = ".mew" ascii nocase
        $str_mew = "MEW" ascii wide
        $str_mew_sec = ".MEW" ascii

    condition:
        any of them
}

rule MEW_Packer_EP {
    meta:
        description = "MEW packed file - by entry point pattern"
        author = "rBAT Project"
        packer = "MEW"
        weight = 85

    strings:
        $mew_ep = { 60 6A 00 6A 00 FF 35 00 00 00 00 8D 85 00 10 00 00 50 FF 15 }

    condition:
        any of them
}

rule Upack_Packer_Section {
    meta:
        description = "Upack packed file - by section name"
        author = "rBAT Project"
        packer = "Upack"
        weight = 85

    strings:
        $section_upack = ".upack" ascii nocase
        $str_upack = "Upack" ascii wide

    condition:
        any of them
}

rule Upack_Packer_EP {
    meta:
        description = "Upack packed file - by entry point pattern"
        author = "rBAT Project"
        packer = "Upack"
        weight = 85

    strings:
        $upack_ep = { 4C 8D 44 24 10 50 68 00 10 00 00FF 15 }

    condition:
        any of them
}

rule MPRESS_Packer_Section {
    meta:
        description = "MPRESS packed file - by section name"
        author = "rBAT Project"
        packer = "MPRESS"
        weight = 85

    strings:
        $section_mpress = ".mpress" ascii nocase
        $section_upx = ".upx" ascii nocase
        $str_mpress = "mpress" ascii wide
        $str_mpr = ".MPR" ascii

    condition:
        any of them
}

rule WinUpack_Packer {
    meta:
        description = "WinUpack packed file"
        author = "rBAT Project"
        packer = "WinUpack"
        weight = 80

    strings:
        $winupack = { 55 8B EC 83 C4 ?? 53 56 57 8B 5D 08 8B 4B 04 8B 73 08 56 }

    condition:
        any of them
}

rule WWPack_Packer_Section {
    meta:
        description = "WWPack packed file - by section name"
        author = "rBAT Project"
        packer = "WWPACK"
        weight = 80

    strings:
        $section_wwpack = ".wwpack" ascii nocase
        $str_wwpack = "WWPACK" ascii

    condition:
        any of them
}

rule NSPack_Packer {
    meta:
        description = "NSPack packed file"
        author = "rBAT Project"
        packer = "NSPack"
        weight = 80

    strings:
        $nspack_ep = { 55 8B EC 83 EC ?? 8B 45 08 50 8B 45 0C 50 }
        $str_nspack = ".nsp" ascii nocase

    condition:
        any of them
}

rule ECLiPT_Packer {
    meta:
        description = "ECLiPT packed file"
        author = "rBAT Project"
        packer = "ECLiPT"
        weight = 80

    strings:
        $str_eclipt = ".ecl" ascii nocase
        $str_eclipt_sec = "ECLiPT" ascii

    condition:
        any of them
}

rule Shrinker_Packer {
    meta:
        description = "Shrinker packed file"
        author = "rBAT Project"
        packer = "Shrinker"
        weight = 80

    strings:
        $str_shrinker = ".shr" ascii nocase
        $str_shrinker_sec = "Shrinker" ascii

    condition:
        any of them
}

rule kkrunchy_Packer {
    meta:
        description = "kkrunchy packed file"
        author = "rBAT Project"
        packer = "kkrunchy"
        weight = 75

    strings:
        $section_kkr = ".kkr" ascii nocase
        $str_kkr = "kkrunchy" ascii

    condition:
        any of them
}

rule PEBundle_Packer {
    meta:
        description = "PEBundle packed file"
        author = "rBAT Project"
        packer = "PEBundle"
        weight = 80

    strings:
        $section_pebundle = ".pebundle" ascii nocase
        $str_pebundle = "PEBundle" ascii

    condition:
        any of them
}

rule ACK_Packer {
    meta:
        description = "ACK packed file"
        author = "rBAT Project"
        packer = "ACK"
        weight = 75

    strings:
        $section_ack = ".ack" ascii nocase
        $str_ack = "ACK!" ascii

    condition:
        any of them
}

rule Stealth_Packer {
    meta:
        description = "Stealth packed file"
        author = "rBAT Project"
        packer = "Stealth"
        weight = 75

    strings:
        $str_stealth = ".stealth" ascii nocase

    condition:
        any of them
}

rule Morphine_Packer {
    meta:
        description = "Morphine packed file"
        author = "rBAT Project"
        packer = "Morphine"
        weight = 75

    strings:
        $str_morphine = "Morphine" ascii

    condition:
        any of them
}

rule ArmPack_Packer {
    meta:
        description = "ArmPack packed file"
        author = "rBAT Project"
        packer = "ArmPack"
        weight = 80

    strings:
        $section_armpack = ".armpack" ascii nocase
        $str_armpack = "ArmPack" ascii

    condition:
        any of them
}

rule Pelock_Packer {
    meta:
        description = "PE-Lock packed file"
        author = "rBAT Project"
        packer = "PE-Lock"
        weight = 75

    strings:
        $str_pelock = ".pelock" ascii nocase

    condition:
        any of them
}

rule BoxedApp_Packer {
    meta:
        description = "BoxedApp packed file"
        author = "rBAT Project"
        packer = "BoxedApp"
        weight = 75

    strings:
        $str_boxedapp = "BoxedApp" ascii

    condition:
        any of them
}