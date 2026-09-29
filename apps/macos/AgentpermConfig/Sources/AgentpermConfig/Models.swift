import Foundation

enum JSONValue: Codable, Hashable, CustomStringConvertible {
  case string(String)
  case integer(Int)
  case number(Double)
  case bool(Bool)
  case object([String: JSONValue])
  case array([JSONValue])
  case null

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() {
      self = .null
    } else if let value = try? container.decode(Bool.self) {
      self = .bool(value)
    } else if let value = try? container.decode(Int.self) {
      self = .integer(value)
    } else if let value = try? container.decode(Double.self) {
      self = .number(value)
    } else if let value = try? container.decode(String.self) {
      self = .string(value)
    } else if let value = try? container.decode([String: JSONValue].self) {
      self = .object(value)
    } else if let value = try? container.decode([JSONValue].self) {
      self = .array(value)
    } else {
      throw DecodingError.dataCorruptedError(
        in: container, debugDescription: "Unsupported JSON value")
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .string(let value): try container.encode(value)
    case .integer(let value): try container.encode(value)
    case .number(let value): try container.encode(value)
    case .bool(let value): try container.encode(value)
    case .object(let value): try container.encode(value)
    case .array(let value): try container.encode(value)
    case .null: try container.encodeNil()
    }
  }

  var description: String {
    switch self {
    case .string(let value): return value
    default:
      guard let data = try? JSONEncoder.sorted.encode(self) else { return "<invalid JSON>" }
      return String(decoding: data, as: UTF8.self)
    }
  }
}

extension JSONEncoder {
  static var sorted: JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return encoder
  }
}

enum AppMode: String, CaseIterable, Identifiable {
  case explain
  case configure

  var id: String { rawValue }
  var label: String {
    switch self {
    case .explain: "Explain"
    case .configure: "Propose Changes"
    }
  }
}

enum ExplanationDecision: String {
  case allow, ask, deny
  case noOpinion = "no-opinion"
  case unknown

  var label: String {
    switch self {
    case .allow: "Allowed"
    case .ask: "Approval required"
    case .deny: "Denied"
    case .noOpinion: "No matching rule"
    case .unknown: "Unknown"
    }
  }
}

struct ExplanationResult: Identifiable {
  let contextName: String
  let directory: String
  let decision: ExplanationDecision
  let output: String
  let policyFiles: [String]

  var id: String { directory }
}

enum SafetyLevel: String, Codable, CaseIterable {
  case readOnly = "read_only"
  case mixed
  case uncertain

  var label: String {
    switch self {
    case .readOnly: "Read-only"
    case .mixed: "Mixed"
    case .uncertain: "Uncertain"
    }
  }
}

struct RepositoryContext: Codable, Hashable, Identifiable {
  let path: String
  let name: String
  let evidence: String
  let score: Int

  var id: String { path }
}

struct PolicyTarget: Codable, Hashable, Identifiable {
  let id: String
  let path: String
  let scope: String
  let contexts: [String]
  let exists: Bool

  var label: String {
    let name = URL(fileURLWithPath: path).lastPathComponent
    if scope == "global" { return "Global · \(name)" }
    if contexts.count > 1 { return "Shared by \(contexts.count) repositories · \(name)" }
    let context = contexts.first ?? path
    return "\(URL(fileURLWithPath: context).lastPathComponent) · \(name)"
  }
}

struct RuleProposal: Codable, Hashable, Identifiable {
  let id: String
  let rule: JSONValue
  let decision: PolicyDecision
  let rationale: String
  let globalTarget: String
  let candidateProjectTargets: [String]
  var selectedTargets: [String]
  let allowExamples: [String]
  let rejectExamples: [String]
  let replaces: [JSONValue]
  var selected: Bool

  enum CodingKeys: String, CodingKey {
    case id, rule, decision, rationale, selected, replaces
    case globalTarget = "global_target"
    case candidateProjectTargets = "candidate_project_targets"
    case selectedTargets = "selected_targets"
    case allowExamples = "allow_examples"
    case rejectExamples = "reject_examples"
  }
}

enum PolicyDecision: String, Codable, CaseIterable {
  case allow, ask, deny
}

struct RejectedPart: Codable, Hashable, Identifiable {
  let segment: String
  let reason: String

  var id: String { segment + reason }
}

struct PolicyProposal: Codable, Hashable {
  let summary: String
  let safety: SafetyLevel
  let completeCommandWillBeAllowed: Bool
  var rules: [RuleProposal]
  let rejectedParts: [RejectedPart]
  let notes: [String]

  enum CodingKeys: String, CodingKey {
    case summary, safety, rules, notes
    case completeCommandWillBeAllowed = "complete_command_will_be_allowed"
    case rejectedParts = "rejected_parts"
  }
}

struct PreparedFile: Codable, Identifiable, Hashable {
  let targetID: String
  let path: String
  let diff: String

  var id: String { path }

  enum CodingKeys: String, CodingKey {
    case path, diff
    case targetID = "target_id"
  }
}

struct CodexResult {
  let proposal: PolicyProposal
  let threadID: String?
}

enum ReviewPhase: Equatable {
  case composing
  case analysing
  case reviewing
  case revising
  case applying
  case applied
  case failed(String)
}

enum ReviewError: LocalizedError {
  case message(String)

  var errorDescription: String? {
    switch self {
    case .message(let value): value
    }
  }
}
