import Foundation
import Testing

@testable import AgentpermConfig

@Test func arbitraryStructuredRuleRoundTripsWithoutSwiftSchemaKnowledge() throws {
  let source = Data(
    #"{"SQL(read-only)":{"dialect":"sqlite","effects":{"only":["read"]},"future":7}}"#.utf8)

  let value = try JSONDecoder().decode(JSONValue.self, from: source)
  let encoded = try JSONEncoder.sorted.encode(value)
  let decoded = try JSONDecoder().decode(JSONValue.self, from: encoded)

  #expect(decoded == value)
  #expect(value.description.contains(#""future":7"#))
}

@Test func proposalDecodesStringTransportForSimpleAndStructuredRules() throws {
  let data = Data(
    #"{"summary":"safe","safety":"read_only","complete_command_will_be_allowed":true,"rules":[{"id":"one","rule":"Python(readonly)","decision":"allow","rationale":"AST checked","global_target":"target-1","candidate_project_targets":[],"selected_targets":["target-1"],"allow_examples":["python -c 'print(1)'"],"reject_examples":[],"replaces":["{\"SQL(old)\":{\"dialect\":\"sqlite\"}}"],"selected":true}],"rejected_parts":[],"notes":[]}"#
      .utf8)

  let proposal = try JSONDecoder().decode(PolicyProposal.self, from: data)

  #expect(proposal.rules[0].rule == .string("Python(readonly)"))
  #expect(proposal.rules[0].replaces.count == 1)
  #expect(proposal.rules[0].selectedTargets == ["target-1"])
}

@Test func preparedPlanFileUsesOpaqueTargetIDAndBackendDiff() throws {
  let data = Data(
    #"{"target_id":"policy-source-v1-abc","path":"/tmp/.agent-permissions.jsonc","diff":"--- old\n+++ new\n"}"#
      .utf8)

  let file = try JSONDecoder().decode(PreparedFile.self, from: data)

  #expect(file.targetID == "policy-source-v1-abc")
  #expect(file.diff.contains("+++ new"))
}

@Test @MainActor func changingReviewedInputInvalidatesTheProposal() {
  let model = AppModel(command: "git status")
  model.proposal = PolicyProposal(
    summary: "reviewed",
    safety: .readOnly,
    completeCommandWillBeAllowed: true,
    rules: [],
    rejectedParts: [],
    notes: []
  )
  model.phase = .reviewing

  model.command = "git diff"

  #expect(model.proposal == nil)
  #expect(model.preparedFiles.isEmpty)
  #expect(model.phase == .composing)
  #expect(model.statusDetail.contains("Analyze again"))
}

@Test func settingsMigrateWorkflowsThatStillContainTheOldModeField() throws {
  let data = Data(
    #"{"workflows":[{"id":"6B63D93F-C352-4C86-84A2-4CB1E46CC051","name":"Read only","mode":"read_only","instructions":"Only reads"}]}"#
      .utf8)

  let settings = try JSONDecoder().decode(AppSettings.self, from: data)

  #expect(settings.workflows[0].name == "Read only")
  #expect(settings.workflows[0].instructions == "Only reads")
}

@Test func apiNegotiatesCapabilitiesBeforeUsingStructuredSources() async throws {
  let executable = try mockExecutable(
    body: #"""
      input="$(cat)"
      case "$input" in
        *'"operation":"info"'*)
          printf '%s\n' '{"protocol_version":1,"ok":true,"result":{"agentperm_version":"test","operations":["explain","sources","rule.describe","policy.plan","policy.apply","policy.undo"]}}'
          ;;
        *'"operation":"sources"'*)
          printf '%s\n' '{"protocol_version":1,"ok":true,"result":{"cwd":"/tmp","targets":[{"id":"opaque","path":"/tmp/.agent-permissions.jsonc","scope":"project","contexts":["/tmp"],"exists":false}]}}'
          ;;
        *) exit 9 ;;
      esac
      """#)
  let api = try AgentpermAPI(pathOverride: executable.path)

  let targets = try await api.targets(contexts: ["/tmp"])

  #expect(targets.map(\.id) == ["opaque"])
}

@Test func incompatibleAgentpermGetsAnActionableUpgradeError() async throws {
  let executable = try mockExecutable(body: "printf 'old agentperm\\n' >&2\nexit 2")
  let api = try AgentpermAPI(pathOverride: executable.path)

  do {
    _ = try await api.targets(contexts: ["/tmp"])
    Issue.record("Expected compatibility negotiation to fail")
  } catch {
    #expect(error.localizedDescription.contains("Upgrade agentperm"))
    #expect(error.localizedDescription.contains("Config JSON API"))
  }
}

private func mockExecutable(body: String) throws -> URL {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  let executable = directory.appendingPathComponent("agentperm-mock")
  try Data("#!/bin/sh\nset -eu\n\(body)\n".utf8).write(to: executable)
  try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
  return executable
}
