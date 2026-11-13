rule text_plain { strings: $a = "powershell" condition: $a }
rule text_nocase { strings: $a = "PowerShell" nocase condition: $a }
rule text_wide { strings: $a = "invoice" wide condition: $a }
rule text_wide_ascii { strings: $a = "invoice" wide ascii condition: #a >= 2 }
rule text_fullword { strings: $a = "cmd" fullword condition: $a }
rule text_xor { strings: $a = "This program" xor condition: $a }
rule text_xor_range { strings: $a = "http://" xor(1-10) condition: $a }
rule text_escapes { strings: $a = "line1\nline2\x00" condition: $a }
rule hex_basic { strings: $h = { 4D 5A 90 00 } condition: $h at 0 }
rule hex_wild { strings: $h = { 4D 5A ?? 00 } condition: $h }
rule hex_nibble { strings: $h = { 50 4? 00 00 } condition: $h }
rule hex_jump { strings: $h = { 68 74 [2-6] 3A 2F 2F } condition: $h }
rule hex_alt { strings: $h = { 6A ( 70 | 71 | 72 ) 65 67 } condition: $h }
rule hex_not { strings: $h = { 41 ~42 43 } condition: $h }
rule regex_basic { strings: $r = /https?:\/\/[a-z0-9.\-]+\/[a-z]+/ condition: $r }
rule regex_nocase { strings: $r = /invoice_[0-9]{4}/i condition: #r == 2 }
rule regex_dotall { strings: $r = /BEGIN.END/s condition: $r }
rule cond_uint { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }
rule cond_uint_be { condition: uint32be(0) == 0x89504E47 }
rule cond_filesize { condition: filesize > 1KB and filesize < 1MB }
rule cond_count { strings: $a = "AAAA" condition: #a > 3 }
rule cond_offset { strings: $a = "MARK" condition: @a[2] - @a[1] == 100 }
rule cond_in { strings: $a = "MARK" condition: $a in (0..50) }
rule cond_any { strings: $a = "zzz1" $b = "MARK" $c = "zzz2" condition: any of them }
rule cond_all { strings: $a = "MARK" $b = "AAAA" condition: all of them }
rule cond_n_of { strings: $a1 = "MARK" $a2 = "AAAA" $a3 = "nope" condition: 2 of ($a*) }
rule cond_percent { strings: $a = "MARK" $b = "nope" condition: 50% of them }
rule cond_none { strings: $a = "nope1" $b = "nope2" condition: none of them }
rule cond_for_of { strings: $a = "MARK" $b = "AAAA" condition: for all of them : ( # > 1 ) }
rule cond_for_in { strings: $a = "AAAA" condition: for any i in (1..#a) : ( @a[i] % 2 == 1 ) }
rule cond_rule_ref { condition: cond_filesize and not cond_none }
rule cond_arith { condition: (filesize \ 2) * 2 + filesize % 2 == filesize and (1 << 4) == 16 and (0xF0 >> 4) == 0xF and (6 & 3) == 2 and (6 | 1) == 7 and (6 ^ 2) == 4 }
rule cond_undefined { condition: not (uint32(filesize + 10) == 0) }
rule cond_defined { condition: defined uint8(0) and not defined uint8(filesize) }
private rule priv_base { strings: $a = "MARK" condition: $a }
rule uses_private { condition: priv_base }
rule tagged : alpha beta { meta: author = "test" score = 7 ok = true strings: $a = "MARK" condition: $a }
rule anon_strings { strings: $ = "MARK" $ = "AAAA" condition: all of them }
rule of_in_range { strings: $a = "MARK" $b = "AAAA" condition: any of them in (0..20) }
rule of_rules { condition: any of (text_*) }
