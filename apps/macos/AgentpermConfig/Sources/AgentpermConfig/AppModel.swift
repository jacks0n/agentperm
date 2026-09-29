import AppKit
import Foundation
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
  @Published var mode: AppMode = .explain
  @Published var command: String {
    didSet {
      if command != oldValue { inputDidChange() }
    }
  }
  @Published var phase: ReviewPhase = .composing
  @Published var repositories: [RepositoryContext] = []
  @Published var selectedRepositoryPaths = Set<String>()
  @Published var repositorySearch = ""
  @Published var repositoryStatus = ""
  @Published var proposal: PolicyProposal?
  @Published var preparedFiles: [PreparedFile] = []
  @Published var policyTargets: [PolicyTarget] = []
  @Published var selectedDiffPath: String?
  @Published var feedback = ""
  @Published var statusDetail = ""
  @Published var isDemo = false
  @Published var settings: AppSettings
  @Published var settingsMessage = ""
  @Published var explanationResults: [ExplanationResult] = []
  @Published var isExplaining = false
  @Published var explanationError: String?
  @Published var adHocInstructions = "" {
    didSet { inputDidChange() }
  }

  private let codex = CodexService()
  private var threadID: String?
  private var planID: String?
  private var undoID: String?
  private var discoveryTask: Task<Void, Never>?
  private var planningTask: Task<Void, Never>?
  private var inputRevision = 0
  private var reviewedCommand: String?
  private var reviewedRepositories: [RepositoryContext] = []
  private var reviewedTargets: [PolicyTarget] = []

  init(command: String? = nil) {
    self.command =
      command?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
      ? command! : ""
    self.settings = SettingsStore.load()
  }

  var selectedRepositories: [RepositoryContext] {
    repositories.filter { selectedRepositoryPaths.contains($0.path) }
  }

  var workflowChoices: [ReviewWorkflow] {
    [
      ReviewWorkflow(
        id: ReviewWorkflow.adHocID,
        name: "Ad hoc…",
        instructions: adHocInstructions
      )
    ] + settings.workflows
  }

  var activeWorkflow: ReviewWorkflow {
    if settings.selectedWorkflowID == ReviewWorkflow.adHocID {
      return workflowChoices[0]
    }
    return settings.selectedWorkflow
  }

  var isAdHocWorkflow: Bool { settings.selectedWorkflowID == ReviewWorkflow.adHocID }

  var filteredRepositories: [RepositoryContext] {
    guard !repositorySearch.isEmpty else { return repositories }
    return repositories.filter {
      $0.name.localizedCaseInsensitiveContains(repositorySearch)
        || $0.path.localizedCaseInsensitiveContains(repositorySearch)
    }
  }

  var canAnalyse: Bool {
    !command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && phase == .composing
  }

  var canApply: Bool { !isDemo && !preparedFiles.isEmpty }

  var canExplain: Bool {
    !command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      && !isExplaining
  }

  func start() {
    NSApp.activate(ignoringOtherApps: true)
    refreshRepositories()
    if ProcessInfo.processInfo.arguments.contains("--demo") {
      loadDemo()
    }
  }

  func accept(url: URL) {
    guard url.scheme == "agentperm-config" else { return }
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    if let encoded = components?.queryItems?.first(where: { $0.name == "command" })?.value,
      let data = Data(base64Encoded: Self.standardBase64(encoded)),
      let value = String(data: data, encoding: .utf8)
    {
      command = value
    } else if let clipboard = NSPasteboard.general.string(forType: .string) {
      command = clipboard
    }
    discard()
    mode = url.host == "configure" ? .configure : .explain
    refreshRepositories()
    if mode == .explain { explain() }
    NSApp.activate(ignoringOtherApps: true)
  }

  nonisolated static func standardBase64(_ value: String) -> String {
    var normalized = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    normalized += String(repeating: "=", count: (4 - normalized.count % 4) % 4)
    return normalized
  }

  func refreshRepositories() {
    discoveryTask?.cancel()
    repositoryStatus = "Indexing repositories…"
    let currentCommand = command
    discoveryTask = Task {
      let roots = discoveryRoots()
      let found = await RepositoryDiscovery.discover(
        for: currentCommand,
        roots: roots,
        exclusions: settings.repositoryExclusions
      )
      guard !Task.isCancelled else { return }
      let previousSelection = selectedRepositoryPaths
      repositories = found
      selectedRepositoryPaths.formIntersection(Set(found.map(\.path)))
      if selectedRepositoryPaths.isEmpty {
        let strong = found.filter { $0.score >= 20 }.prefix(6)
        selectedRepositoryPaths = Set(strong.map(\.path))
      }
      if selectedRepositoryPaths != previousSelection { inputDidChange() }
      repositoryStatus = "Found \(found.count) repositories and worktrees"
    }
  }

  func toggleRepository(_ repository: RepositoryContext) {
    if selectedRepositoryPaths.contains(repository.path) {
      selectedRepositoryPaths.remove(repository.path)
    } else {
      selectedRepositoryPaths.insert(repository.path)
    }
    inputDidChange()
  }

  func clearRepositories() {
    selectedRepositoryPaths.removeAll()
    inputDidChange()
  }

  func selectSuggestedRepositories() {
    selectedRepositoryPaths = Set(repositories.filter { $0.score >= 3 }.prefix(6).map(\.path))
    inputDidChange()
  }

  func toggleAllFilteredRepositories() {
    let paths = Set(filteredRepositories.map(\.path))
    if paths.isSubset(of: selectedRepositoryPaths) {
      selectedRepositoryPaths.subtract(paths)
    } else {
      selectedRepositoryPaths.formUnion(paths)
    }
    inputDidChange()
  }

  func analyse() {
    guard canAnalyse else { return }
    let analysedCommand = command
    let analysedRepositories = selectedRepositories
    let analysedWorkflow = activeWorkflow
    let revision = inputRevision
    phase = .analysing
    statusDetail = "Codex is classifying command segments and read-only families…"
    Task {
      do {
        let api = try AgentpermAPI(pathOverride: settings.agentpermPath)
        let targets = try await api.targets(contexts: analysedRepositories.map(\.path))
        let result = try await codex.analyse(
          command: analysedCommand,
          repositories: analysedRepositories,
          targets: targets,
          settings: settings,
          workflow: analysedWorkflow
        )
        guard inputRevision == revision else {
          throw ReviewError.message("Inputs changed during analysis. Run Analyze again.")
        }
        policyTargets = targets
        threadID = result.threadID
        proposal = result.proposal
        reviewedCommand = analysedCommand
        reviewedRepositories = analysedRepositories
        reviewedTargets = targets
        try await refreshPreparedFiles()
        phase = .reviewing
        statusDetail = "Proposal ready"
      } catch {
        phase = .failed(error.localizedDescription)
      }
    }
  }

  func explain() {
    guard canExplain else { return }
    isExplaining = true
    explanationError = nil
    statusDetail = "Resolving merged policy across selected contexts…"
    Task {
      do {
        explanationResults = try await ExplanationService.explain(
          command: command,
          repositories: selectedRepositories,
          agentpermPath: settings.agentpermPath
        )
        statusDetail =
          "Explained \(explanationResults.count) context\(explanationResults.count == 1 ? "" : "s")"
      } catch {
        explanationError = error.localizedDescription
      }
      isExplaining = false
    }
  }

  func configureCurrentCommand() {
    mode = .configure
    if proposal == nil { phase = .composing }
  }

  func revise() {
    let trimmed = feedback.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return }
    guard let threadID else {
      phase = .failed("This proposal has no resumable Codex thread. Start a fresh analysis.")
      return
    }
    includeRepositoriesMentioned(in: trimmed)
    let revisedCommand = command
    let revisedRepositories = selectedRepositories
    let revisedWorkflow = activeWorkflow
    let revision = inputRevision
    phase = .revising
    statusDetail = "Codex is revising the complete proposal…"
    Task {
      do {
        let api = try AgentpermAPI(pathOverride: settings.agentpermPath)
        let targets = try await api.targets(contexts: revisedRepositories.map(\.path))
        let result = try await codex.revise(
          feedback: trimmed,
          threadID: threadID,
          repositories: revisedRepositories,
          targets: targets,
          settings: settings,
          workflow: revisedWorkflow
        )
        guard inputRevision == revision else {
          throw ReviewError.message("Inputs changed during revision. Revise again.")
        }
        policyTargets = targets
        self.threadID = result.threadID
        proposal = result.proposal
        reviewedCommand = revisedCommand
        reviewedRepositories = revisedRepositories
        reviewedTargets = targets
        feedback = ""
        try await refreshPreparedFiles()
        phase = .reviewing
        statusDetail = "Revised proposal ready"
      } catch {
        phase = .failed(error.localizedDescription)
      }
    }
  }

  func setRuleSelected(id: String, selected: Bool) {
    guard var value = proposal, let index = value.rules.firstIndex(where: { $0.id == id }) else {
      return
    }
    value.rules[index].selected = selected
    proposal = value
    refreshPlan()
  }

  func toggleTarget(ruleID: String, path: String) {
    guard var value = proposal, let index = value.rules.firstIndex(where: { $0.id == ruleID })
    else { return }
    var targets = value.rules[index].selectedTargets
    if targets.contains(path) {
      guard targets.count > 1 else { return }
      targets.removeAll { $0 == path }
    } else {
      targets.append(path)
    }
    value.rules[index].selectedTargets = targets.sorted()
    proposal = value
    refreshPlan()
  }

  func targetOptions(for rule: RuleProposal) -> [(String, String)] {
    policyTargets.map { ($0.id, $0.label) }
  }

  func apply() {
    guard let proposal, let planID, let reviewedCommand else { return }
    phase = .applying
    statusDetail = "Applying, validating, and checking safety boundaries…"
    Task {
      do {
        let result = try await PolicyApplier.apply(
          planID: planID,
          proposal: proposal,
          command: reviewedCommand,
          repositories: reviewedRepositories,
          targets: reviewedTargets,
          agentpermPath: settings.agentpermPath
        )
        undoID = result.undoID
        statusDetail = result.summary
        phase = .applied
      } catch {
        phase = .failed(error.localizedDescription)
      }
    }
  }

  func undo() {
    guard let undoID else { return }
    Task {
      do {
        try await PolicyApplier.undo(planID: undoID, agentpermPath: settings.agentpermPath)
        self.undoID = nil
        statusDetail = "All policy files were restored"
        phase = .reviewing
        try await refreshPreparedFiles()
      } catch {
        phase = .failed(error.localizedDescription)
      }
    }
  }

  func discard() {
    undoID = nil
    planID = nil
    proposal = nil
    preparedFiles = []
    selectedDiffPath = nil
    threadID = nil
    feedback = ""
    reviewedCommand = nil
    reviewedRepositories = []
    reviewedTargets = []
    isDemo = false
    phase = .composing
    statusDetail = ""
  }

  func returnToReview() {
    phase = proposal == nil ? .composing : .reviewing
  }

  func saveSettings() {
    do {
      if settings.selectedWorkflowID != ReviewWorkflow.adHocID,
        !settings.workflows.contains(where: { $0.id == settings.selectedWorkflowID })
      {
        settings.selectedWorkflowID = settings.workflows.first?.id ?? ReviewWorkflow.readOnly.id
      }
      var persisted = settings
      if persisted.selectedWorkflowID == ReviewWorkflow.adHocID {
        persisted.selectedWorkflowID = persisted.workflows.first?.id ?? ReviewWorkflow.readOnly.id
      }
      try SettingsStore.save(persisted)
      settingsMessage = "Saved"
      inputDidChange()
      refreshRepositories()
    } catch {
      settingsMessage = error.localizedDescription
    }
  }

  func persistWorkflowSelection() {
    inputDidChange()
    if !isAdHocWorkflow { try? SettingsStore.save(settings) }
  }

  func addWorkflow() {
    let workflow = ReviewWorkflow(
      id: UUID(),
      name: "Custom workflow",
      instructions: "Describe which rules and decisions Codex should propose."
    )
    settings.workflows.append(workflow)
    settings.selectedWorkflowID = workflow.id
  }

  func removeSelectedWorkflow() {
    guard settings.workflows.count > 1 else { return }
    settings.workflows.removeAll { $0.id == settings.selectedWorkflowID }
    settings.selectedWorkflowID = settings.workflows[0].id
  }

  private func refreshPreparedFiles() async throws {
    guard let proposal else {
      preparedFiles = []
      planID = nil
      return
    }
    guard proposal.rules.contains(where: { $0.selected }) else {
      preparedFiles = []
      planID = nil
      selectedDiffPath = nil
      return
    }
    let api = try AgentpermAPI(pathOverride: settings.agentpermPath)
    let plan = try await api.plan(
      proposal: proposal,
      contexts: selectedRepositories.map(\.path),
      targets: policyTargets
    )
    planID = plan.planID
    preparedFiles = plan.files
    if selectedDiffPath == nil || !preparedFiles.contains(where: { $0.path == selectedDiffPath }) {
      selectedDiffPath = preparedFiles.first?.path
    }
  }

  private func refreshPlan() {
    planningTask?.cancel()
    planningTask = Task {
      do {
        try await refreshPreparedFiles()
      } catch is CancellationError {
      } catch {
        phase = .failed(error.localizedDescription)
      }
    }
  }

  private func inputDidChange() {
    inputRevision += 1
    guard !isDemo, phase != .applying, proposal != nil, undoID == nil else { return }
    planningTask?.cancel()
    planID = nil
    proposal = nil
    preparedFiles = []
    selectedDiffPath = nil
    threadID = nil
    reviewedCommand = nil
    reviewedRepositories = []
    reviewedTargets = []
    phase = .composing
    statusDetail = "Inputs changed · run Analyze again"
  }

  private func includeRepositoriesMentioned(in text: String) {
    let lower = text.lowercased()
    for repository in repositories
    where
      lower.contains(repository.name.lowercased()) || lower.contains(repository.path.lowercased())
    {
      selectedRepositoryPaths.insert(repository.path)
    }
  }

  private func discoveryRoots() -> [String] {
    RepositoryDiscovery.homeDiscoveryRoots(additionalRoots: settings.repositoryRoots)
  }

  private func loadDemo() {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let demoTarget = PolicyTarget(
      id: "demo-global", path: "\(home)/.agent-permissions.jsonc", scope: "global",
      contexts: [home], exists: true)
    policyTargets = [demoTarget]
    command =
      "aws logs filter-log-events --log-group-name /aws/lambda/napi | jq '.events' > report.json && ./deploy.sh"
    isDemo = true
    proposal = PolicyProposal(
      summary:
        "Two read-only segments can be generalized; the file write and deployment remain blocked.",
      safety: .mixed,
      completeCommandWillBeAllowed: false,
      rules: [
        RuleProposal(
          id: "aws-logs-read",
          rule: .string(
            "Shell(aws values(--profile,--region,--log-group-name,--start-time,--end-time) logs {describe-log-groups,describe-log-streams,filter-log-events,get-log-events} only(--profile,--region,--log-group-name,--start-time,--end-time))"
          ),
          decision: .allow,
          rationale:
            "These CloudWatch Logs operations retrieve metadata or events and exclude every create, put, update, and delete operation.",
          globalTarget: demoTarget.id,
          candidateProjectTargets: [],
          selectedTargets: [demoTarget.id],
          allowExamples: [
            "aws logs describe-log-groups", "aws logs get-log-events --log-group-name example",
          ],
          rejectExamples: [
            "aws logs delete-log-group --log-group-name example",
            "aws logs put-retention-policy --log-group-name example",
          ],
          replaces: [],
          selected: true
        ),
        RuleProposal(
          id: "jq-read",
          rule: .string("Shell(jq)"),
          decision: .allow,
          rationale:
            "jq transforms input without mutating external state when output redirection is evaluated separately.",
          globalTarget: demoTarget.id,
          candidateProjectTargets: [],
          selectedTargets: [demoTarget.id],
          allowExamples: ["printf '[]' | jq '.[]'"],
          rejectExamples: ["jq '.' input.json > output.json"],
          replaces: [],
          selected: true
        ),
      ],
      rejectedParts: [
        RejectedPart(segment: "> report.json", reason: "Writes a file"),
        RejectedPart(segment: "./deploy.sh", reason: "Local deployment script has side effects"),
      ],
      notes: ["The complete command will continue to prompt because two effects remain unapproved."]
    )
    preparedFiles = [
      PreparedFile(
        targetID: demoTarget.id,
        path: demoTarget.path,
        diff: "--- \(demoTarget.path)\n+++ \(demoTarget.path)\n@@ demo proposal @@")
    ]
    selectedDiffPath = demoTarget.path
    phase = .reviewing
    statusDetail = "Interactive demo · applying is disabled"
  }
}
