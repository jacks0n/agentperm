import Foundation

enum SecretRedactor {
  static func redact(_ command: String) -> String {
    var result = command
    let assignment =
      /(?i)\b([A-Z_][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*)=(?:'[^']*'|"[^"]*"|[^\s;&|]+)/
    result.replace(assignment) { match in
      "\(match.1)=<redacted>"
    }

    let option =
      /(?i)(--?[a-z0-9_-]*(?:password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)[a-z0-9_-]*)(?:=|\s+)(?:'[^']*'|"[^"]*"|[^\s;&|]+)/
    result.replace(option) { match in
      "\(match.1)=<redacted>"
    }
    return result
  }

  static func containsSensitiveName(_ text: String) -> Bool {
    text.range(
      of: #"(password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)"#,
      options: [.regularExpression, .caseInsensitive]
    ) != nil
  }
}
