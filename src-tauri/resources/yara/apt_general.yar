/*
 * Starter / placeholder rules for suspicious script-style strings often seen in cradles.
 * Populate with curated sets from upstream feeds such as:
 *   https://github.com/YARAHQ/YARA-Forge
 *   https://github.com/Yara-Rules/rules
 */

rule suspicious_script_cradle_strings {
  meta:
    source = "apt_general.yar"
    description = "Multiple suspicious scripting API tokens in one buffer"
  strings:
    $a = "DownloadString" nocase
    $b = "Invoke-Expression" nocase
    $c = "FromBase64String" nocase
    $d = "powershell -enc" nocase
    $e = "mshta" nocase wide ascii
  condition:
    3 of them
}
