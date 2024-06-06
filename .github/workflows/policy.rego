package semgrep.policy

deny[msg] {
    result := input[_]
    msg := sprintf("Found vulnerability: %s with severity %s", [result.extra.message, result.extra.severity])
}

# Política original para falhar o build em vulnerabilidades críticas
deny_critical[msg] {
    result := input[_]
    result.extra.severity == "CRITICAL"
    msg := sprintf("Build failed due to a critical vulnerability: %s", [result.extra.message])
}
