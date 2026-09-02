file(READ "${STARLOADER_PACKAGE_SCRIPT}" script)
foreach(required IN ITEMS
        "ProtectedExecutable" "ProtectedOutputRoot" "DestinationRoot" "SignToolPath"
        "WindowsDefenderCommand" "Get-AuthenticodeSignature" "TimeStamperCertificate"
        "verify /pa /all /v" "SHA-256 Authenticode" "-ScanType 3" "Get-FileHash" "not a ready-to-distribute package")
    if(NOT script MATCHES "${required}")
        message(FATAL_ERROR "Release packaging script lacks required fail-closed check: ${required}")
    endif()
endforeach()
foreach(forbidden IN ITEMS "--preset qt-mingw" "Remove-Item" "zip'leyip dagit")
    if(script MATCHES "${forbidden}")
        message(FATAL_ERROR "Release packaging script contains forbidden ordinary-build behavior: ${forbidden}")
    endif()
endforeach()
