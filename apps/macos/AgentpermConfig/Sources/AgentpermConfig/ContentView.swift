import AppKit
import SwiftUI

struct ContentView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    VStack(spacing: 0) {
      HStack(spacing: 18) {
        Label("Agentperm Config", systemImage: "checkmark.shield")
          .font(.headline)
        Picker("Mode", selection: $model.mode) {
          ForEach(AppMode.allCases) { mode in
            Text(mode.label).tag(mode)
          }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(width: 260)
        Spacer()
        SettingsLink { Label("Settings", systemImage: "gearshape") }
          .help("Command-line tools, repository discovery, instructions, and workflows")
      }
      .padding(.horizontal, 18)
      .frame(height: 52)
      .background(.bar)
      Divider()

      Group {
        if model.mode == .explain {
          ExplainView(model: model)
        } else {
          configurationContent
        }
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }
    .background(Color(nsColor: .windowBackgroundColor))
  }

  @ViewBuilder private var configurationContent: some View {
    Group {
      switch model.phase {
      case .composing:
        ComposeView(model: model)
      case .analysing, .revising:
        WorkingView(model: model)
      case .reviewing, .applying:
        ReviewView(model: model)
      case .applied:
        AppliedView(model: model)
      case .failed(let message):
        FailureView(model: model, message: message)
      }
    }
  }
}

private struct ExplainView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    HSplitView {
      inputPane.frame(
        minWidth: 390, idealWidth: 440, maxHeight: .infinity, alignment: .top)
      resultsPane.frame(minWidth: 520, maxHeight: .infinity)
    }
  }

  private var inputPane: some View {
    VStack(alignment: .leading, spacing: 16) {
      Header(
        title: "Why did this need permission?",
        subtitle: "Compare the effective policy globally and inside any repository.")

      GroupBox("Command or shell program") {
        TextEditor(text: $model.command)
          .font(.system(.body, design: .monospaced))
          .scrollContentBackground(.hidden)
          .frame(height: 110)
          .padding(6)
      }

      Label(
        "Global policy is always explained first; selected repositories add their local policy layers.",
        systemImage: "globe"
      )
      .font(.caption)
      .foregroundStyle(.secondary)
      RepositoryPicker(
        model: model,
        title: "Compare repository policies",
        help: "Select repositories where this command should be explained."
      )

      HStack {
        Text(model.statusDetail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
        Spacer()
        Button {
          model.explain()
        } label: {
          if model.isExplaining {
            ProgressView().controlSize(.small)
          } else {
            Label("Explain", systemImage: "sparkle.magnifyingglass")
          }
        }
        .buttonStyle(.borderedProminent)
        .keyboardShortcut(.return, modifiers: .command)
        .disabled(!model.canExplain)
      }
    }
    .padding(22)
  }

  @ViewBuilder private var resultsPane: some View {
    if let error = model.explanationError {
      ContentUnavailableView(
        "Couldn’t explain this command",
        systemImage: "exclamationmark.triangle",
        description: Text(error)
      )
    } else if model.explanationResults.isEmpty {
      ContentUnavailableView(
        "Effective policy explanation",
        systemImage: "text.magnifyingglass",
        description: Text(
          "Run Explain to see the winning rule, compound-command segments, and contributing policy files for every selected context."
        )
      )
    } else {
      ScrollView {
        LazyVStack(alignment: .leading, spacing: 14) {
          HStack {
            VStack(alignment: .leading, spacing: 3) {
              Text("Effective decisions").font(.title2.weight(.semibold))
              Text("The same command can resolve differently as project policies enter scope.")
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Propose a change") { model.configureCurrentCommand() }
              .buttonStyle(.borderedProminent)
          }
          ForEach(model.explanationResults) { result in
            ExplanationCard(result: result)
          }
        }
        .padding(20)
      }
      .background(Color(nsColor: .textBackgroundColor).opacity(0.35))
    }
  }

}

private struct ExplanationCard: View {
  let result: ExplanationResult

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack {
        Image(systemName: icon).foregroundStyle(color)
        VStack(alignment: .leading, spacing: 2) {
          Text(result.contextName).font(.headline)
          Text(shortPath(result.directory)).font(.caption).foregroundStyle(.secondary)
        }
        Spacer()
        Text(result.decision.label.uppercased())
          .font(.caption2.bold())
          .foregroundStyle(color)
          .padding(.horizontal, 8)
          .padding(.vertical, 4)
          .background(color.opacity(0.12), in: Capsule())
      }

      Text(result.output)
        .font(.system(.caption, design: .monospaced))
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(11)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))

      if !result.policyFiles.isEmpty {
        HStack(spacing: 7) {
          Text("POLICY FILES").sectionLabel()
          ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
              ForEach(result.policyFiles, id: \.self) { path in
                Button(shortPath(path)) {
                  NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
              }
            }
          }
        }
      }
    }
    .padding(14)
    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    .overlay(RoundedRectangle(cornerRadius: 12).stroke(color.opacity(0.22)))
  }

  private var color: Color {
    switch result.decision {
    case .allow: .green
    case .ask, .noOpinion: .orange
    case .deny: .red
    case .unknown: .secondary
    }
  }

  private var icon: String {
    switch result.decision {
    case .allow: "checkmark.circle.fill"
    case .ask, .noOpinion: "questionmark.circle.fill"
    case .deny: "xmark.octagon.fill"
    case .unknown: "questionmark.diamond.fill"
    }
  }

  private func shortPath(_ path: String) -> String {
    path.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
  }
}

private struct RepositoryPicker: View {
  @ObservedObject var model: AppModel
  var title = "Repository contexts"
  var help: String? = nil
  @State private var isPresented = false

  var body: some View {
    VStack(alignment: .leading, spacing: 9) {
      HStack(spacing: 9) {
        Text(title).font(.headline)
        Spacer()
        Button {
          isPresented.toggle()
        } label: {
          Label(selectionLabel, systemImage: "chevron.up.chevron.down")
        }
        .popover(isPresented: $isPresented, arrowEdge: .bottom) {
          pickerPopover
        }
        Button {
          model.refreshRepositories()
        } label: {
          Image(systemName: "arrow.clockwise")
        }
        .help("Refresh repository discovery")
      }

      if let help {
        Text(help)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(2)
      }

      if model.selectedRepositories.isEmpty {
        Text("No repositories selected")
          .font(.caption)
          .foregroundStyle(.secondary)
      } else {
        ScrollView(.horizontal, showsIndicators: false) {
          HStack(spacing: 7) {
            ForEach(model.selectedRepositories) { repository in
              Button {
                model.toggleRepository(repository)
              } label: {
                Label(repository.name, systemImage: "xmark.circle.fill")
              }
              .buttonStyle(.bordered)
              .controlSize(.small)
              .help("Remove \(repository.path)")
            }
          }
        }
      }
    }
  }

  private var selectionLabel: String {
    let count = model.selectedRepositoryPaths.count
    return count == 0 ? "Choose repositories" : "\(count) selected"
  }

  private var pickerPopover: some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack {
        VStack(alignment: .leading, spacing: 2) {
          Text("Select repositories").font(.headline)
          Text(model.repositoryStatus).font(.caption).foregroundStyle(.secondary)
        }
        Spacer()
        Button("Suggested") { model.selectSuggestedRepositories() }
          .disabled(!model.repositories.contains { $0.score >= 3 })
        Button("Clear") { model.clearRepositories() }
          .disabled(model.selectedRepositoryPaths.isEmpty)
      }

      TextField("Filter by name or path", text: $model.repositorySearch)
        .textFieldStyle(.roundedBorder)

      Button {
        model.toggleAllFilteredRepositories()
      } label: {
        Label(
          model.repositorySearch.isEmpty ? "All repositories" : "All filtered results",
          systemImage: selectAllIcon
        )
      }
      .buttonStyle(.plain)
      .disabled(model.filteredRepositories.isEmpty)

      List(model.filteredRepositories) { repository in
        Button {
          model.toggleRepository(repository)
        } label: {
          HStack(spacing: 10) {
            Image(
              systemName: model.selectedRepositoryPaths.contains(repository.path)
                ? "checkmark.square.fill" : "square"
            )
            .foregroundStyle(
              model.selectedRepositoryPaths.contains(repository.path)
                ? Color.accentColor : Color.secondary)
            VStack(alignment: .leading, spacing: 2) {
              Text(repository.name).fontWeight(.medium)
              Text(shortPath(repository.path))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }
            Spacer()
            if repository.score > 0 {
              Text("match \(repository.score)").font(.caption2).foregroundStyle(.secondary)
            }
          }
          .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
      }
    }
    .padding(14)
    .frame(width: 470, height: 440)
  }

  private func shortPath(_ path: String) -> String {
    path.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
  }

  private var selectAllIcon: String {
    let paths = Set(model.filteredRepositories.map(\.path))
    if paths.isEmpty || paths.isDisjoint(with: model.selectedRepositoryPaths) { return "square" }
    if paths.isSubset(of: model.selectedRepositoryPaths) { return "checkmark.square.fill" }
    return "minus.square.fill"
  }
}

private struct ComposeView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      HStack {
        Header(
          title: "Propose configuration changes",
          subtitle: "Codex proposes. You choose exactly what changes.")
        Spacer()
        Picker("Workflow", selection: $model.settings.selectedWorkflowID) {
          ForEach(model.workflowChoices) { workflow in
            Text(workflow.name).tag(workflow.id)
          }
        }
        .frame(width: 280)
        .onChange(of: model.settings.selectedWorkflowID) { _, _ in
          model.persistWorkflowSelection()
        }
      }

      if model.isAdHocWorkflow {
        GroupBox("One-off proposal instructions") {
          VStack(alignment: .leading, spacing: 8) {
            TextEditor(text: $model.adHocInstructions)
              .frame(height: 72)
              .padding(5)
              .background(
                Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6)
              )
            Text(
              "These instructions apply only to this proposal. Agentperm still parses and validates every proposed rule before review."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
          }
          .padding(5)
        }
      }

      GroupBox("Command") {
        TextEditor(text: $model.command)
          .font(.system(.body, design: .monospaced))
          .scrollContentBackground(.hidden)
          .frame(minHeight: 125)
          .padding(6)
      }

      RepositoryPicker(
        model: model,
        title: "Repository evidence and targets",
        help:
          "Optional for global tools; select every repo whose local scripts or configuration matter."
      )

      HStack {
        Label(model.repositoryStatus, systemImage: "externaldrive.badge.magnifyingglass")
          .font(.caption)
          .foregroundStyle(.secondary)
        Spacer()
        Button("Analyse") { model.analyse() }
          .keyboardShortcut(.return, modifiers: .command)
          .buttonStyle(.borderedProminent)
          .disabled(!model.canAnalyse)
      }
    }
    .padding(24)
  }
}

private struct WorkingView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    VStack(spacing: 22) {
      ProgressView().controlSize(.large)
      Text(model.phase == .revising ? "Revising proposal" : "Analysing command")
        .font(.title2.weight(.semibold))
      Text(model.statusDetail)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      Text(
        "Codex is running headlessly in a read-only sandbox. No policy file can change during this step."
      )
      .font(.caption)
      .foregroundStyle(.tertiary)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

private struct ReviewView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    VStack(spacing: 0) {
      reviewHeader
      Divider()
      HSplitView {
        proposalPane.frame(minWidth: 380, idealWidth: 440)
        diffPane.frame(minWidth: 520)
      }
      Divider()
      feedbackBar
    }
    .overlay {
      if model.phase == .applying {
        ZStack {
          Color.black.opacity(0.18).ignoresSafeArea()
          VStack(spacing: 14) {
            ProgressView().controlSize(.large)
            Text("Applying as one transaction…").font(.headline)
            Text(model.statusDetail).font(.caption).foregroundStyle(.secondary)
          }
          .padding(26)
          .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
        }
      }
    }
  }

  private var reviewHeader: some View {
    HStack(spacing: 14) {
      Image(systemName: safetyIcon)
        .font(.title2)
        .foregroundStyle(safetyColor)
      VStack(alignment: .leading, spacing: 3) {
        Text(model.proposal?.summary ?? "Policy proposal")
          .font(.headline)
          .lineLimit(2)
        HStack(spacing: 12) {
          Text(model.activeWorkflow.name)
          Text(model.proposal?.safety.label ?? "")
          Text(
            "\(model.preparedFiles.count) configuration file\(model.preparedFiles.count == 1 ? "" : "s")"
          )
          if model.proposal?.completeCommandWillBeAllowed == false {
            Text("Complete command will still prompt")
          }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
      }
      Spacer()
      Button("Discard") { model.discard() }
      Button("Apply selected") { model.apply() }
        .buttonStyle(.borderedProminent)
        .keyboardShortcut(.return, modifiers: .command)
        .disabled(!model.canApply)
        .help(
          model.isDemo
            ? "Apply is disabled in demo mode"
            : "Apply every selected change as one verified transaction")
    }
    .padding(18)
  }

  private var proposalPane: some View {
    ScrollView {
      LazyVStack(alignment: .leading, spacing: 14) {
        Text("PROPOSED RULES").sectionLabel()
        ForEach(model.proposal?.rules ?? []) { rule in
          RuleCard(model: model, rule: rule)
        }

        if let rejected = model.proposal?.rejectedParts, !rejected.isEmpty {
          Text("NOT WHITELISTED").sectionLabel().padding(.top, 6)
          ForEach(rejected) { part in
            HStack(alignment: .top, spacing: 9) {
              Image(systemName: "xmark.octagon.fill").foregroundStyle(.orange)
              VStack(alignment: .leading, spacing: 3) {
                Text(part.segment).font(.system(.body, design: .monospaced))
                Text(part.reason).font(.caption).foregroundStyle(.secondary)
              }
            }
            .padding(10)
            .background(Color.orange.opacity(0.07), in: RoundedRectangle(cornerRadius: 9))
          }
        }

        if let notes = model.proposal?.notes, !notes.isEmpty {
          Text("NOTES").sectionLabel().padding(.top, 6)
          ForEach(notes, id: \.self) { note in
            Label(note, systemImage: "info.circle")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
        }
      }
      .padding(16)
    }
  }

  private var diffPane: some View {
    VStack(spacing: 0) {
      HStack {
        Text("CONFIGURATION DIFF").sectionLabel()
        Spacer()
        if !model.preparedFiles.isEmpty {
          Picker(
            "File",
            selection: Binding(
              get: { model.selectedDiffPath ?? model.preparedFiles[0].path },
              set: { model.selectedDiffPath = $0 }
            )
          ) {
            ForEach(model.preparedFiles) { file in
              Text(shortPath(file.path)).tag(file.path)
            }
          }
          .labelsHidden()
          .frame(maxWidth: 330)
        }
      }
      .padding(14)
      Divider()
      if let selected = model.preparedFiles.first(where: { $0.path == model.selectedDiffPath })
        ?? model.preparedFiles.first
      {
        DiffView(diff: selected.diff)
      } else {
        ContentUnavailableView(
          "No file changes", systemImage: "doc.badge.checkmark",
          description: Text("All selected rules are already present."))
      }
    }
    .background(Color(nsColor: .textBackgroundColor).opacity(0.45))
  }

  private var feedbackBar: some View {
    HStack(alignment: .bottom, spacing: 12) {
      VStack(alignment: .leading, spacing: 5) {
        Text("REQUEST A REVISION").sectionLabel()
        TextEditor(text: $model.feedback)
          .font(.body)
          .frame(minHeight: 48, maxHeight: 80)
          .padding(5)
          .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
          .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.secondary.opacity(0.25)))
      }
      Button("Send feedback") { model.revise() }
        .disabled(model.feedback.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        .help("Examples: make it global; apply to network-api too; narrow the AWS family")
    }
    .padding(14)
  }

  private var safetyIcon: String {
    switch model.proposal?.safety {
    case .readOnly: "checkmark.shield.fill"
    case .mixed: "shield.lefthalf.filled"
    default: "questionmark.diamond.fill"
    }
  }

  private var safetyColor: Color {
    switch model.proposal?.safety {
    case .readOnly: .green
    case .mixed: .orange
    default: .yellow
    }
  }

  private func shortPath(_ path: String) -> String {
    path.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
  }
}

private struct RuleCard: View {
  @ObservedObject var model: AppModel
  let rule: RuleProposal
  @State private var expanded = false

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack(alignment: .top) {
        Toggle(
          "",
          isOn: Binding(
            get: { rule.selected },
            set: { model.setRuleSelected(id: rule.id, selected: $0) }
          )
        )
        .labelsHidden()
        VStack(alignment: .leading, spacing: 6) {
          HStack(alignment: .firstTextBaseline) {
            Text(rule.decision.rawValue.uppercased())
              .font(.caption2.bold())
              .foregroundStyle(decisionColor)
              .padding(.horizontal, 6)
              .padding(.vertical, 2)
              .background(decisionColor.opacity(0.12), in: Capsule())
            Text(rule.rule.description)
              .font(.system(.callout, design: .monospaced))
              .textSelection(.enabled)
          }
          Text(rule.rationale)
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      }

      HStack {
        Menu {
          ForEach(model.targetOptions(for: rule), id: \.0) { option in
            Button {
              model.toggleTarget(ruleID: rule.id, path: option.0)
            } label: {
              Label(
                option.1,
                systemImage: rule.selectedTargets.contains(option.0) ? "checkmark" : "circle")
            }
          }
        } label: {
          Label(
            "\(rule.selectedTargets.count) target\(rule.selectedTargets.count == 1 ? "" : "s")",
            systemImage: "folder.badge.gearshape")
        }
        .menuStyle(.borderlessButton)
        Spacer()
        Button(expanded ? "Hide safety envelope" : "Show safety envelope") { expanded.toggle() }
          .buttonStyle(.plain)
          .font(.caption)
          .foregroundStyle(.tint)
      }

      if expanded {
        VStack(alignment: .leading, spacing: 8) {
          ExampleList(
            title: "Will allow", icon: "checkmark.circle.fill", color: .green,
            examples: rule.allowExamples)
          ExampleList(
            title: "Must remain blocked", icon: "xmark.circle.fill", color: .orange,
            examples: rule.rejectExamples)
          if !rule.replaces.isEmpty {
            ExampleList(
              title: "Replaces narrower rules", icon: "arrow.triangle.2.circlepath", color: .blue,
              examples: rule.replaces.map(\.description))
          }
        }
        .padding(.leading, 26)
      }
    }
    .padding(12)
    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 11))
    .overlay(RoundedRectangle(cornerRadius: 11).stroke(Color.secondary.opacity(0.16)))
    .opacity(rule.selected ? 1 : 0.58)
  }

  private var decisionColor: Color {
    switch rule.decision {
    case .allow: .green
    case .ask: .orange
    case .deny: .red
    }
  }
}

private struct ExampleList: View {
  let title: String
  let icon: String
  let color: Color
  let examples: [String]

  var body: some View {
    if !examples.isEmpty {
      VStack(alignment: .leading, spacing: 4) {
        Label(title, systemImage: icon).font(.caption.weight(.semibold)).foregroundStyle(color)
        ForEach(examples, id: \.self) { example in
          Text(example).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
        }
      }
    }
  }
}

private struct DiffView: View {
  let diff: String

  var body: some View {
    ScrollView([.horizontal, .vertical]) {
      LazyVStack(alignment: .leading, spacing: 0) {
        ForEach(
          Array(diff.split(separator: "\n", omittingEmptySubsequences: false).enumerated()),
          id: \.offset
        ) { _, line in
          Text(String(line))
            .font(.system(size: 12.5, design: .monospaced))
            .foregroundStyle(color(for: line))
            .padding(.vertical, 1)
            .textSelection(.enabled)
        }
      }
      .padding(14)
    }
  }

  private func color(for line: Substring) -> Color {
    if line.hasPrefix("+") && !line.hasPrefix("+++") { return .green }
    if line.hasPrefix("-") && !line.hasPrefix("---") { return .red }
    if line.hasPrefix("@@") { return .blue }
    if line.hasPrefix("+++") || line.hasPrefix("---") { return .secondary }
    return .primary
  }
}

private struct AppliedView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    VStack(spacing: 18) {
      Image(systemName: "checkmark.seal.fill").font(.system(size: 54)).foregroundStyle(.green)
      Text("Policies applied and verified").font(.title2.weight(.semibold))
      Text(model.statusDetail).foregroundStyle(.secondary)
      Text(
        "Every selected file validated, positive examples became allowed, and mutating neighbours remained blocked."
      )
      .multilineTextAlignment(.center)
      .frame(maxWidth: 520)
      HStack {
        Button("Undo all changes") { model.undo() }
        Button("Done") { model.discard() }.buttonStyle(.borderedProminent)
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

private struct FailureView: View {
  @ObservedObject var model: AppModel
  let message: String

  var body: some View {
    VStack(spacing: 18) {
      Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 50)).foregroundStyle(
        .orange)
      Text("The operation stopped safely").font(.title2.weight(.semibold))
      ScrollView {
        Text(message).font(.system(.body, design: .monospaced)).textSelection(.enabled)
      }
      .frame(maxWidth: 700, maxHeight: 260)
      Text("No partial policy change has been left behind.").foregroundStyle(.secondary)
      HStack {
        Button("Discard") { model.discard() }
        Button("Back to proposal") { model.returnToReview() }.buttonStyle(.borderedProminent)
      }
    }
    .padding(30)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

private struct Header: View {
  let title: String
  let subtitle: String

  var body: some View {
    HStack(spacing: 14) {
      Image(systemName: "checkmark.shield").font(.system(size: 34)).foregroundStyle(.tint)
      VStack(alignment: .leading, spacing: 3) {
        Text(title).font(.largeTitle.weight(.semibold))
        Text(subtitle).foregroundStyle(.secondary)
      }
    }
  }
}

extension Text {
  fileprivate func sectionLabel() -> some View {
    font(.caption.weight(.bold)).foregroundStyle(.secondary).tracking(0.7)
  }
}
