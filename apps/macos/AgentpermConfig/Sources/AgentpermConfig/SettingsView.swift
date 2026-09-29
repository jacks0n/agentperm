import SwiftUI

struct SettingsView: View {
  @ObservedObject var model: AppModel

  private var selectedWorkflowIndex: Int? {
    model.settings.workflows.firstIndex { $0.id == model.settings.selectedWorkflowID }
      ?? model.settings.workflows.indices.first
  }

  private var settingsWorkflowSelection: Binding<UUID> {
    Binding {
      if model.settings.workflows.contains(where: { $0.id == model.settings.selectedWorkflowID }) {
        return model.settings.selectedWorkflowID
      }
      return model.settings.workflows.first?.id ?? ReviewWorkflow.readOnly.id
    } set: {
      model.settings.selectedWorkflowID = $0
    }
  }

  var body: some View {
    Form {
      Section("Command-line tools") {
        TextField("Codex executable (blank = PATH)", text: $model.settings.codexPath)
        TextField("agentperm executable (blank = PATH)", text: $model.settings.agentpermPath)
        TextField("Profile (optional)", text: $model.settings.codexProfile)
        TextField("Model (optional)", text: $model.settings.codexModel)
        Text(
          "The app inherits PATH from macOS. Overrides may use absolute paths or ~ and are useful for GUI-specific environments."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
      }

      Section("Policy and repository discovery") {
        Text(
          "Git repositories are discovered across your home directory. System, privacy-protected, application, cache, and build directories are skipped unless explicitly added below."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
        LabeledContent("Additional roots") {
          TextEditor(text: linesBinding(\.repositoryRoots))
            .font(.system(.body, design: .monospaced))
            .frame(height: 58)
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.secondary.opacity(0.2)))
        }
        LabeledContent("Excluded directory names") {
          TextEditor(text: linesBinding(\.repositoryExclusions))
            .font(.system(.caption, design: .monospaced))
            .frame(height: 58)
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.secondary.opacity(0.2)))
        }
      }

      Section("Global instructions") {
        TextEditor(text: $model.settings.globalInstructions)
          .frame(height: 75)
          .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.secondary.opacity(0.2)))
        Text(
          "These instructions are sent with every workflow. Deterministic path confinement, reviewed diffs, validation, and rollback cannot be overridden."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
      }

      Section("Workflows") {
        HStack {
          Picker("Workflow", selection: settingsWorkflowSelection) {
            ForEach(model.settings.workflows) { workflow in
              Text(workflow.name).tag(workflow.id)
            }
          }
          Button {
            model.addWorkflow()
          } label: {
            Image(systemName: "plus")
          }
          Button {
            model.removeSelectedWorkflow()
          } label: {
            Image(systemName: "minus")
          }
          .disabled(model.settings.workflows.count <= 1)
        }

        if let index = selectedWorkflowIndex {
          TextField("Name", text: workflowBinding(index, \.name))
          Text(
            "Instructions guide Codex; agentperm independently parses and validates proposed rules."
          )
          .font(.caption)
          .foregroundStyle(.secondary)
          TextEditor(text: workflowBinding(index, \.instructions))
            .frame(height: 115)
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.secondary.opacity(0.2)))
        }
      }
    }
    .formStyle(.grouped)
    .safeAreaInset(edge: .bottom) {
      HStack {
        Text(model.settingsMessage).font(.caption).foregroundStyle(.secondary)
        Spacer()
        Button("Save") { model.saveSettings() }
          .buttonStyle(.borderedProminent)
          .keyboardShortcut("s", modifiers: .command)
      }
      .padding(12)
      .background(.bar)
    }
  }

  private func linesBinding(_ keyPath: WritableKeyPath<AppSettings, [String]>) -> Binding<String> {
    Binding {
      model.settings[keyPath: keyPath].joined(separator: "\n")
    } set: { value in
      model.settings[keyPath: keyPath] = value.split(separator: "\n").map {
        $0.trimmingCharacters(in: .whitespaces)
      }.filter { !$0.isEmpty }
    }
  }

  private func workflowBinding<Value>(
    _ index: Int,
    _ keyPath: WritableKeyPath<ReviewWorkflow, Value>
  ) -> Binding<Value> {
    Binding {
      model.settings.workflows[index][keyPath: keyPath]
    } set: { value in
      model.settings.workflows[index][keyPath: keyPath] = value
    }
  }
}
