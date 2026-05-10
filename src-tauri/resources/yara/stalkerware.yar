/*
 * Complements windows-spy-signatures.yaml — path/process-oriented ASCII/WIDE strings.
 */

rule stalkerware_hoverwatch_strings {
  meta:
    source = "stalkerware.yar"
  strings:
    $n = "hoverwatch" nocase wide ascii
    $p = "Hoverwatch" nocase wide ascii
  condition:
    any of them
}

rule stalkerware_flexispy_strings {
  meta:
    source = "stalkerware.yar"
  strings:
    $n = "flexispy" nocase wide ascii
    $p = "FlexiSpy" nocase wide ascii
  condition:
    any of them
}

rule stalkerware_spyrix_strings {
  meta:
    source = "stalkerware.yar"
  strings:
    $n = "spyrix" nocase wide ascii
    $p = "Spyrix" nocase wide ascii
  condition:
    any of them
}

rule stalkerware_webwatcher_strings {
  meta:
    source = "stalkerware.yar"
  strings:
    $n = "webwatcher" nocase wide ascii
    $p = "WebWatcher" nocase wide ascii
  condition:
    any of them
}

rule stalkerware_teamviewer_path_hint {
  meta:
    source = "stalkerware.yar"
  strings:
    $p = "TeamViewer" nocase wide ascii
  condition:
    $p
}

rule stalkerware_anydesk_path_hint {
  meta:
    source = "stalkerware.yar"
  strings:
    $p = "AnyDesk" nocase wide ascii
  condition:
    $p
}

rule stalkerware_refog_strings {
  meta:
    source = "stalkerware.yar"
  strings:
    $n = "refog" nocase wide ascii
    $p = "REFOG" nocase wide ascii
  condition:
    any of them
}

rule stalkerware_activtrak_strings {
  meta:
    source = "stalkerware.yar"
  strings:
    $n = "activtrak" nocase wide ascii
    $p = "ActivTrak" nocase wide ascii
  condition:
    any of them
}
