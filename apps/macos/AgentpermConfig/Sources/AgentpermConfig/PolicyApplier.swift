import Foundation

struct ApplyResult {
  let summary: String
  let undoID: String
}

enum PolicyApplier {
  static func apply(
    planID: String,
    proposal: PolicyProposal,
    command: String,
    repositories: [RepositoryContext],
    targets: [PolicyTarget],
    agentpermPath: String = ""
  ) async throws -> ApplyResult {
    let api = try AgentpermAPI(pathOverride: agentpermPath)
    let applied = try await api.apply(planID: planID)
    do {
      try await verify(
        api: api,
        proposal: proposal,
        command: command,
        repositories: repositories,
        targets: targets
      )
    } catch {
      do {
        _ = try await api.undo(planID: applied.undoID)
      } catch let rollbackError {
        throw ReviewError.message(
          "Verification failed: \(error.localizedDescription)\n\nAgentperm could not safely roll back because policy state changed: \(rollbackError.localizedDescription)"
        )
      }
      throw error
    }
    return ApplyResult(
      summary:
        "Applied and verified \(applied.appliedFiles) policy file\(applied.appliedFiles == 1 ? "" : "s")",
      undoID: applied.undoID
    )
  }

  static func undo(planID: String, agentpermPath: String = "") async throws {
    let api = try AgentpermAPI(pathOverride: agentpermPath)
    _ = try await api.undo(planID: planID)
  }

  private static func verify(
    api: AgentpermAPI,
    proposal: PolicyProposal,
    command: String,
    repositories: [RepositoryContext],
    targets: [PolicyTarget]
  ) async throws {
    let targetsByID = Dictionary(uniqueKeysWithValues: targets.map { ($0.id, $0) })
    for rule in proposal.rules where rule.selected {
      for targetID in rule.selectedTargets {
        guard let target = targetsByID[targetID] else {
          throw ReviewError.message("Applied rule refers to an unknown target: \(targetID)")
        }
        for context in target.contexts {
          for example in rule.allowExamples.prefix(8) {
            let explanation = try await api.explain(command: example, cwd: context)
            guard explanation.decision == rule.decision.rawValue else {
              throw ReviewError.message(
                "Expected \(rule.decision.rawValue) in \(context): \(example)\n\(explanation.rationale)"
              )
            }
          }
          for example in rule.rejectExamples.prefix(8) {
            let explanation = try await api.explain(command: example, cwd: context)
            guard explanation.decision != "allow" else {
              throw ReviewError.message(
                "Unsafe neighbour became allowed in \(context): \(example)")
            }
          }
        }
      }
    }

    let contexts = Set(
      [FileManager.default.homeDirectoryForCurrentUser.path] + repositories.map(\.path))
    let hasGlobalRule = proposal.rules.contains { rule in
      rule.selected && rule.selectedTargets.contains { targetsByID[$0]?.scope == "global" }
    }
    for cwd in contexts {
      let relevant = proposal.rules.contains { rule in
        rule.selected
          && rule.selectedTargets.contains { targetsByID[$0]?.contexts.contains(cwd) == true }
      }
      guard hasGlobalRule || relevant else { continue }
      let explanation = try await api.explain(command: command, cwd: cwd)
      if proposal.completeCommandWillBeAllowed, explanation.decision != "allow" {
        throw ReviewError.message(
          "The complete command was expected to be allowed in \(cwd):\n\(explanation.rationale)")
      }
      if !proposal.completeCommandWillBeAllowed, explanation.decision == "allow" {
        throw ReviewError.message(
          "The proposal says the complete command remains blocked, but it is allowed in \(cwd)")
      }
    }
  }
}
