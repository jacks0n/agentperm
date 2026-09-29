import Foundation

enum ExplanationService {
  static func explain(
    command: String,
    repositories: [RepositoryContext],
    agentpermPath: String = ""
  ) async throws -> [ExplanationResult] {
    let api = try AgentpermAPI(pathOverride: agentpermPath)
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    var contexts: [(name: String, path: String)] = [("Global policy baseline", home)]
    contexts += repositories.map { ($0.name, $0.path) }

    return try await withThrowingTaskGroup(
      of: (Int, ExplanationResult).self,
      returning: [ExplanationResult].self
    ) { group in
      for (index, context) in contexts.enumerated() {
        group.addTask {
          let explanation = try await api.explain(command: command, cwd: context.path)
          let detail =
            ([explanation.rationale]
            + explanation.segments.map {
              "\($0.decision) \($0.command) — \($0.rationale)"
            }).joined(separator: "\n")
          return (
            index,
            ExplanationResult(
              contextName: context.name,
              directory: explanation.cwd,
              decision: ExplanationDecision(rawValue: explanation.decision) ?? .unknown,
              output: detail,
              policyFiles: explanation.sources.map(\.path)
            )
          )
        }
      }
      var indexed: [(Int, ExplanationResult)] = []
      for try await result in group { indexed.append(result) }
      return indexed.sorted { $0.0 < $1.0 }.map(\.1)
    }
  }
}
