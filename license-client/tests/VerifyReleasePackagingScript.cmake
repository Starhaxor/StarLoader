file(READ "${STARLOADER_PACKAGE_SCRIPT}" script)
foreach(required IN ITEMS
        "ProtectedExecutable" "ProtectedOutputRoot" "DestinationRoot" "SignToolPath"
        "WindowsDefenderCommand" "Get-AuthenticodeSignature" "TimeStamperCertificate"
        "verify /pa /all /v" "SHA-256 Authenticode" "-ScanType 3" "Get-FileHash"
        "NON_DISTRIBUTABLE.txt" "not a ready-to-distribute package")
    if(NOT script MATCHES "${required}")
        message(FATAL_ERROR "Release packaging script lacks required fail-closed check: ${required}")
    endif()
endforeach()

set(copy_statement "Copy-Item -LiteralPath $executablePath -Destination $stagedExecutable")
set(signature_statement "Get-AuthenticodeSignature -LiteralPath $stagedExecutable")
set(signtool_statement "& $signTool verify /pa /all /v $stagedExecutable")
set(defender_statement "& $defender -Scan -ScanType 3 -File $stagedExecutable")
string(FIND "${script}" "${copy_statement}" copy_position)
string(FIND "${script}" "${signature_statement}" signature_position)
string(FIND "${script}" "${signtool_statement}" signtool_position)
string(FIND "${script}" "${defender_statement}" defender_position)
if(copy_position LESS 0 OR signature_position LESS copy_position
        OR signtool_position LESS signature_position OR defender_position LESS signtool_position)
    message(FATAL_ERROR "Release gates must run in order against the staged executable after copying.")
endif()

foreach(forbidden_source_gate IN ITEMS
        "Get-AuthenticodeSignature -LiteralPath $executablePath"
        "& $signTool verify /pa /all /v $executablePath"
        "& $defender -Scan -ScanType 3 -File $executablePath")
    string(FIND "${script}" "${forbidden_source_gate}" forbidden_source_gate_position)
    if(NOT forbidden_source_gate_position EQUAL -1)
        message(FATAL_ERROR "A final release gate still targets the mutable source executable.")
    endif()
endforeach()
foreach(forbidden IN ITEMS "--preset qt-mingw" "Remove-Item" "zip'leyip dagit")
    if(script MATCHES "${forbidden}")
        message(FATAL_ERROR "Release packaging script contains forbidden ordinary-build behavior: ${forbidden}")
    endif()
endforeach()
