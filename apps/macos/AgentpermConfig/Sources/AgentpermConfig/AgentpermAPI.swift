import Foundation

private struct APIEnvelope<Result: Decodable>: Decodable {
  let protocolVersion: Int
  let ok: Bool
  let result: Result?
  let error: APIError?

  enum CodingKeys: String, CodingKey {
    case ok, result, error
    case protocolVersion = "protocol_version"
  }
}

private struct APIError: Decodable {
  let code: String
  let message: String
}

private struct APIInfo: Decodable {
  let agentpermVersion: String
  let operations: [String]

  enum CodingKeys: String, CodingKey {
    case operations
    case agentpermVersion = "agentperm_version"
  }
}

struct SourcesResult: Decodable {
  let cwd: String
  let targets: [PolicyTarget]
}

struct ExplanationSegment: Decodable, Hashable {
  let command: String
  let decision: String
  let rationale: String
}

struct SourceReference: Decodable, Hashable {
  let id: String
  let path: String
}

struct StructuredExplanation: Decodable {
  let cwd: String
  let decision: String
  let rationale: String
  let segments: [ExplanationSegment]
  let sources: [SourceReference]
}

struct RuleDescription: Decodable {
  let canonicalValue: JSONValue
  let display: String
  let kind: String
  let semanticEffect: String
  let validDecisions: [String]

  enum CodingKeys: String, CodingKey {
    case display, kind
    case canonicalValue = "canonical_value"
    case semanticEffect = "semantic_effect"
    case validDecisions = "valid_decisions"
  }
}

struct PolicyPlan: Decodable {
  let planID: String
  let expiresAt: Int
  let files: [PreparedFile]

  enum CodingKeys: String, CodingKey {
    case files
    case planID = "plan_id"
    case expiresAt = "expires_at"
  }
}

struct PolicyApplyResult: Decodable {
  let appliedFiles: Int
  let undoID: String

  enum CodingKeys: String, CodingKey {
    case appliedFiles = "applied_files"
    case undoID = "undo_id"
  }
}

struct PolicyUndoResult: Decodable {
  let restoredFiles: Int

  enum CodingKeys: String, CodingKey {
    case restoredFiles = "restored_files"
  }
}

private struct PolicyEditRequest: Encodable {
  let action: String
  let decision: String
  let rule: JSONValue
  let oldRule: JSONValue?

  enum CodingKeys: String, CodingKey {
    case action, decision, rule
    case oldRule = "old_rule"
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(action, forKey: .action)
    try container.encode(decision, forKey: .decision)
    try container.encode(rule, forKey: .rule)
    if let oldRule { try container.encode(oldRule, forKey: .oldRule) }
  }
}

private struct PolicyFileRequest: Encodable {
  let targetID: String
  let edits: [PolicyEditRequest]

  enum CodingKeys: String, CodingKey {
    case edits
    case targetID = "target_id"
  }
}

actor AgentpermAPI {
  private let executable: String
  private var compatibilityChecked = false

  init(pathOverride: String = "") throws {
    guard let executable = ProcessRunner.executable(named: "agentperm", override: pathOverride)
    else {
      throw ReviewError.message(
        pathOverride.isEmpty
          ? "agentperm was not found on PATH. Set its executable in Settings."
          : "The configured agentperm executable is not executable: \(pathOverride)")
    }
    self.executable = executable
  }

  func targets(contexts: [String]) async throws -> [PolicyTarget] {
    try await ensureCompatible()
    let effective =
      contexts.isEmpty
      ? [FileManager.default.homeDirectoryForCurrentUser.path] : contexts
    var byID: [String: PolicyTarget] = [:]
    for context in effective {
      let result: SourcesResult = try await call([
        "operation": .string("sources"), "cwd": .string(context),
      ])
      for target in result.targets {
        if let existing = byID[target.id] {
          byID[target.id] = PolicyTarget(
            id: existing.id,
            path: existing.path,
            scope: existing.scope == "global" || target.scope == "global" ? "global" : "project",
            contexts: Array(Set(existing.contexts + target.contexts)).sorted(),
            exists: existing.exists || target.exists
          )
        } else {
          byID[target.id] = target
        }
      }
    }
    return byID.values.sorted { ($0.scope, $0.path) < ($1.scope, $1.path) }
  }

  func explain(command: String, cwd: String) async throws -> StructuredExplanation {
    try await ensureCompatible()
    return try await call([
      "operation": .string("explain"),
      "command": .string(command),
      "cwd": .string(cwd),
    ])
  }

  func describe(rule: JSONValue) async throws -> RuleDescription {
    try await ensureCompatible()
    return try await call(["operation": .string("rule.describe"), "value": rule])
  }

  func plan(
    proposal: PolicyProposal,
    contexts: [String],
    targets: [PolicyTarget]
  ) async throws -> PolicyPlan {
    try await ensureCompatible()
    let allowedTargets = Set(targets.map(\.id))
    var editsByTarget: [String: [PolicyEditRequest]] = [:]
    for rule in proposal.rules where rule.selected {
      let description = try await describe(rule: rule.rule)
      guard description.validDecisions.contains(rule.decision.rawValue) else {
        throw ReviewError.message(
          "\(description.display) cannot be used in permissions.\(rule.decision.rawValue)")
      }
      guard !rule.selectedTargets.isEmpty else {
        throw ReviewError.message("\(description.display) has no selected policy target")
      }
      for target in rule.selectedTargets {
        guard allowedTargets.contains(target) else {
          throw ReviewError.message("Codex proposed a target agentperm did not issue: \(target)")
        }
        if rule.replaces.count == 1, let old = rule.replaces.first {
          editsByTarget[target, default: []].append(
            PolicyEditRequest(
              action: "replace", decision: rule.decision.rawValue, rule: rule.rule, oldRule: old))
        } else {
          for old in rule.replaces {
            editsByTarget[target, default: []].append(
              PolicyEditRequest(
                action: "remove", decision: rule.decision.rawValue, rule: old, oldRule: nil))
          }
          editsByTarget[target, default: []].append(
            PolicyEditRequest(
              action: "add", decision: rule.decision.rawValue, rule: rule.rule, oldRule: nil))
        }
      }
    }
    guard !editsByTarget.isEmpty else {
      throw ReviewError.message("There are no selected policy changes")
    }
    let files = editsByTarget.keys.sorted().map {
      PolicyFileRequest(targetID: $0, edits: editsByTarget[$0] ?? [])
    }
    let effectiveContexts =
      contexts.isEmpty
      ? [FileManager.default.homeDirectoryForCurrentUser.path] : contexts
    return try await call([
      "operation": .string("policy.plan"),
      "contexts": .array(effectiveContexts.map(JSONValue.string)),
      "files": try Self.jsonValue(files),
    ])
  }

  func apply(planID: String) async throws -> PolicyApplyResult {
    try await ensureCompatible()
    return try await call(["operation": .string("policy.apply"), "plan_id": .string(planID)])
  }

  func undo(planID: String) async throws -> PolicyUndoResult {
    try await ensureCompatible()
    return try await call(["operation": .string("policy.undo"), "plan_id": .string(planID)])
  }

  private func call<Result: Decodable>(_ fields: [String: JSONValue]) async throws -> Result {
    var request = fields
    request["protocol_version"] = .integer(1)
    let data = try JSONEncoder.sorted.encode(request)
    let result = try await ProcessRunner.run(
      executable: executable,
      arguments: ["api"],
      input: String(decoding: data, as: UTF8.self),
      currentDirectory: FileManager.default.homeDirectoryForCurrentUser.path,
      timeoutSeconds: 30
    )
    guard let response = result.stdout.data(using: String.Encoding.utf8) else {
      throw ReviewError.message("agentperm returned non-UTF-8 output")
    }
    let envelope: APIEnvelope<Result>
    do {
      envelope = try JSONDecoder().decode(APIEnvelope<Result>.self, from: response)
    } catch {
      let detail = (result.stderr + result.stdout).trimmingCharacters(in: .whitespacesAndNewlines)
      throw ReviewError.message("agentperm returned an invalid API response: \(detail)")
    }
    guard envelope.protocolVersion == 1 else {
      throw ReviewError.message(
        "agentperm API protocol \(envelope.protocolVersion) is unsupported by this app")
    }
    guard envelope.ok, let value = envelope.result else {
      let failure = envelope.error
      throw ReviewError.message(
        "agentperm \(failure?.code ?? "error"): \(failure?.message ?? "unknown error")")
    }
    return value
  }

  private func ensureCompatible() async throws {
    guard !compatibilityChecked else { return }
    let info: APIInfo
    do {
      info = try await call(["operation": .string("info")])
    } catch {
      throw ReviewError.message(
        "The configured agentperm does not provide the Config JSON API. Upgrade agentperm or choose a newer executable in Settings.\n\n\(error.localizedDescription)"
      )
    }
    let required = Set([
      "explain", "sources", "rule.describe", "policy.plan", "policy.apply", "policy.undo",
    ])
    let missing = required.subtracting(info.operations)
    guard missing.isEmpty else {
      throw ReviewError.message(
        "agentperm \(info.agentpermVersion) is missing required Config API operations: \(missing.sorted().joined(separator: ", ")). Upgrade agentperm."
      )
    }
    compatibilityChecked = true
  }

  private static func jsonValue<Value: Encodable>(_ value: Value) throws -> JSONValue {
    let data = try JSONEncoder.sorted.encode(value)
    return try JSONDecoder().decode(JSONValue.self, from: data)
  }
}
