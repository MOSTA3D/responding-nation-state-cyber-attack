rule dark_l0rd_rule {
        meta:
                author = "MOSTA_3D"
                description = "This is custom YARA rule for detecting darkl0rd malware"

        strings:
                $domain = "darkl0rd.com"
                $port = "7758"

        condition:
                all of them
}

