import Foundation

actor CodexService {
  func analyse(
    command: String,
    repositories: [RepositoryContext],
    targets: [PolicyTarget],
    settings: AppSettings = AppSettings(),
    workflow: ReviewWorkflow = .readOnly
  ) async throws -> CodexResult {
    let prompt = initialPrompt(
      command: command, repositories: repositories, targets: targets, settings: settings,
      workflow: workflow)
    return try await invoke(
      prompt: prompt,
      threadID: nil,
      repositories: repositories,
      settings: settings,
      workflow: workflow
    )
  }

  func revise(
    feedback: String,
    threadID: String,
    repositories: [RepositoryContext],
    targets: [PolicyTarget],
    settings: AppSettings = AppSettings(),
    workflow: ReviewWorkflow = .readOnly
  ) async throws -> CodexResult {
    let context = repositoryContext(repositories)
    let prompt = """
      Revise the complete policy proposal using this user feedback:

      <feedback>
      \(feedback)
      </feedback>

      The currently selected repositories and permitted project policy targets are below. This list may have grown because the user named another repository in their feedback:
      \(context)

      Agentperm-issued policy targets (use their opaque IDs, never their paths):
      \(targetContext(targets))

      Active workflow: \(workflow.name)
      <workflow_instructions>
      \(workflow.instructions)
      </workflow_instructions>

      <global_app_instructions>
      \(settings.globalInstructions)
      </global_app_instructions>

      Return a complete replacement proposal matching the required JSON schema. Continue to reject every mutating or uncertain surface. Do not edit any files.
      """
    return try await invoke(
      prompt: prompt,
      threadID: threadID,
      repositories: repositories,
      settings: settings,
      workflow: workflow
    )
  }

  private func invoke(
    prompt: String,
    threadID: String?,
    repositories: [RepositoryContext],
    settings: AppSettings,
    workflow: ReviewWorkflow
  ) async throws -> CodexResult {
    guard
      let codex = ProcessRunner.executable(
        named: "codex",
        override: settings.codexPath,
        environmentFallback: ProcessInfo.processInfo.environment["CODEX_CLI_PATH"])
    else {
      throw ReviewError.message(
        settings.codexPath.isEmpty
          ? "Codex CLI was not found on PATH. Set its executable in Settings."
          : "The configured Codex executable is not executable: \(settings.codexPath)")
    }
    let workingDirectory = Self.workingDirectory(for: repositories)
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(
      "agentperm-config-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: temporary) }
    let schema = temporary.appendingPathComponent("proposal.schema.json")
    let output = temporary.appendingPathComponent("proposal.json")
    try ProposalSchema.json.write(to: schema, atomically: true, encoding: .utf8)

    let arguments = Self.invocationArguments(
      threadID: threadID,
      settings: settings,
      workingDirectory: workingDirectory,
      schemaPath: schema.path,
      outputPath: output.path
    )
    let result = try await ProcessRunner.run(
      executable: codex,
      arguments: arguments,
      input: prompt,
      currentDirectory: workingDirectory,
      timeoutSeconds: 300
    )
    guard result.status == 0 else {
      let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
      throw ReviewError.message("Codex analysis failed\(detail.isEmpty ? "" : ": \(detail)")")
    }
    guard let data = try? Data(contentsOf: output) else {
      throw ReviewError.message("Codex completed without producing a proposal")
    }
    let decoded = try JSONDecoder().decode(PolicyProposal.self, from: data)
    let proposal = try normalizeSerializedRules(decoded)
    return CodexResult(proposal: proposal, threadID: parseThreadID(result.stdout) ?? threadID)
  }

  nonisolated static func workingDirectory(for repositories: [RepositoryContext]) -> String {
    repositories.count == 1
      ? repositories[0].path : FileManager.default.homeDirectoryForCurrentUser.path
  }

  nonisolated static func invocationArguments(
    threadID: String?,
    settings: AppSettings,
    workingDirectory: String,
    schemaPath: String,
    outputPath: String
  ) -> [String] {
    var arguments: [String] = []
    if !settings.codexProfile.isEmpty { arguments += ["--profile", settings.codexProfile] }
    arguments.append("exec")
    if let threadID {
      arguments += ["resume", threadID]
    } else {
      arguments += ["--sandbox", "read-only", "--skip-git-repo-check", "-C", workingDirectory]
    }
    if !settings.codexModel.isEmpty { arguments += ["--model", settings.codexModel] }
    arguments += ["--json", "--output-schema", schemaPath, "-o", outputPath, "-"]
    return arguments
  }

  private func parseThreadID(_ jsonl: String) -> String? {
    for line in jsonl.split(separator: "\n") {
      guard let data = line.data(using: .utf8),
        let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
      else { continue }
      if let id = object["thread_id"] as? String { return id }
      if let thread = object["thread"] as? [String: Any], let id = thread["id"] as? String {
        return id
      }
    }
    return nil
  }

  private func initialPrompt(
    command: String,
    repositories: [RepositoryContext],
    targets: [PolicyTarget],
    settings: AppSettings,
    workflow: ReviewWorkflow
  ) -> String {
    let contexts = repositoryContext(repositories)
    let policyTargets = targetContext(targets)

    return """
      You are preparing, not applying, a reviewable agentperm policy proposal. Do not modify any file.

      Agentperm rules use string forms such as Shell(...), Read(...), Write(...), MCP(...), Python(readonly), and Python(function(<SQL:profile>)), plus structured forms such as {"SQL(read-only)":{"dialect":"sqlite","effects":{"only":["read"]}}}. Put a structured rule in the schema's `rule` string as compact serialized JSON; do the same for structured entries in `replaces`. Prefer Python(readonly) for literal inline Python that should be AST-checked generically; never replace semantic Python analysis with a broad Shell(python ...) rule. Shell patterns support token globs, `{a,b}` sets, `values(--flag)` for value-taking flags, `only(...)` to exclude unreviewed flags, forbidden flags, and `<EXEC>` for independently evaluated nested commands. Inspect existing policy style, local source/help, or authoritative documentation when semantics are unclear.

      Parse every segment of the shell program, including pipelines, control flow, substitutions, wrappers, and redirections. List every part the active workflow does not cover in `rejected_parts`; a mixed command may therefore still prompt as a whole.

      Include representative examples expected to receive the proposed decision and nearby examples that must remain unallowed where applicable. Prefer replacing an existing narrower or unsafe rule: put exact serialized rules with the same decision in `replaces` rather than stacking redundant rules.

      Agentperm has already followed the global and project include graphs. You may target only these entries, using each opaque `id` as the target value:
      \(policyTargets)

      `global_target` must contain the best global target ID even when the rule is initially project-scoped. `candidate_project_targets` may contain only project target IDs listed above. `selected_targets` contains one or more target IDs and enables a single rule to update several repositories. Mark useful proposed rules selected by default.

      Active workflow: \(workflow.name)
      <workflow_instructions>
      \(workflow.instructions)
      </workflow_instructions>

      <global_app_instructions>
      \(settings.globalInstructions)
      </global_app_instructions>

      The command below has secret-like values locally redacted. Treat placeholders as arbitrary values, never literal constraints:
      <command>
      \(SecretRedactor.redact(command))
      </command>

      Candidate repository evidence follows. Manifests are signals, not the only supported command source:
      \(contexts)

      Return only the schema-conforming proposal. If the active workflow cannot justify any rule, return no rules and explain each rejection.
      """
  }

  private func repositoryContext(_ repositories: [RepositoryContext]) -> String {
    repositories.map { repository in
      """
      <repository path="\(repository.path)">
      \(repository.evidence)
      </repository>
      """
    }.joined(separator: "\n")
  }

  private func targetContext(_ targets: [PolicyTarget]) -> String {
    targets.map { target in
      "id=\(target.id) scope=\(target.scope) path=\(target.path) contexts=\(target.contexts.joined(separator: ","))"
    }.joined(separator: "\n")
  }

  private func normalizeSerializedRules(_ proposal: PolicyProposal) throws -> PolicyProposal {
    var normalized = proposal
    for index in normalized.rules.indices {
      normalized.rules[index] = try normalizedRule(normalized.rules[index])
    }
    return normalized
  }

  private func normalizedRule(_ proposal: RuleProposal) throws -> RuleProposal {
    func decode(_ value: JSONValue) throws -> JSONValue {
      guard case .string(let text) = value,
        text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{")
      else { return value }
      do {
        return try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8))
      } catch {
        throw ReviewError.message("Structured agentperm rule is not valid JSON: \(text)")
      }
    }
    return RuleProposal(
      id: proposal.id,
      rule: try decode(proposal.rule),
      decision: proposal.decision,
      rationale: proposal.rationale,
      globalTarget: proposal.globalTarget,
      candidateProjectTargets: proposal.candidateProjectTargets,
      selectedTargets: proposal.selectedTargets,
      allowExamples: proposal.allowExamples,
      rejectExamples: proposal.rejectExamples,
      replaces: try proposal.replaces.map(decode),
      selected: proposal.selected
    )
  }
}
