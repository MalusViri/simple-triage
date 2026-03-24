rule ContainsPowerShell : process_execution
{
    meta:
        author = "test"
        description = "Matches powershell strings"
    strings:
        $ps = "powershell.exe"
    condition:
        $ps
}
