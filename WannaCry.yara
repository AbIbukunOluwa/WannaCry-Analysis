rule WannaCry {
    
    meta:
        author = "Ab_Sec"
        description = "Yara rule for WannaCry ransomware"
        last_updated = "2024-01-30"

    strings:
        // wannacry won't run properly without some of these files
        $dropped_files = "tasksche.exe"
        $dropped_files1 = "tasksdl.exe"
        $dropped_files2 = "taskse.exe"
        $dropped_files3 = "@WannaDecryptor@.exe"
        $dropped_files4 = "mssecsvc.exe"
        $dropped_files5 = "lhdfrgui.exe"
        $dropped_files6 = "diskpart.exe"
        $malware_note = "MZ"
        $malware_note1 = ".WNCRY"
        $malware_note2 = ".wnry"
        $malware_note3 = "PADDINGXXPADDING"
        $malware_note4 = "icacls . /grant Everyone:F /T /C /Q"
        $malware_check = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"

    condition:
        $malware_note at 0 and $dropped_files and $dropped_files1 and $dropped_files2 and $dropped_files3 and $dropped_files4 and $dropped_files5 and $dropped_files6 and $malware_note1 and $malware_note2 and $malware_note4 or $malware_check or $malware_note3

}