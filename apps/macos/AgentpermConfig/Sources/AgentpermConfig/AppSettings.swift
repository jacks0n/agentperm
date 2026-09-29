import Foundation

struct ReviewWorkflow: Codable, Hashable, Identifiable {
  var id: UUID
  var name: String
  var instructions: String

  static let adHocID = UUID(uuidString: "AD40C000-0000-4000-8000-000000000001")!

  static let readOnly = ReviewWorkflow(
    id: UUID(uuidString: "6B63D93F-C352-4C86-84A2-4CB1E46CC051")!,
    name: "Read-only generalisation",
    instructions: """
      Propose allow rules only for mechanically proven read-only command surfaces. Split compound commands and leave every write, deletion, execution, upload, interactive edit, output-file mode, or uncertain segment rejected. Classify reusable tools globally and repository-dependent scripts locally. Generalise across the widest safe family instead of copying observed arguments. Group read-only sibling subcommands, vary harmless values, forbid mutating flags, and replace redundant narrower rules. Every non-inherently-observational rule needs representative allowed commands and nearby mutating commands that must remain blocked.
      """
  )
}

struct AppSettings: Codable, Equatable {
  var version = 1
  var codexPath = ""
  var agentpermPath = ""
  var codexProfile = ""
  var codexModel = ""
  var repositoryRoots = ["~/Code", "~/Sites"]
  var repositoryExclusions = [
    "node_modules", ".venv", "target", "cdk.out", ".next", "dist", "build",
  ]
  var globalInstructions = ""
  var workflows = [ReviewWorkflow.readOnly]
  var selectedWorkflowID = ReviewWorkflow.readOnly.id

  var selectedWorkflow: ReviewWorkflow {
    workflows.first(where: { $0.id == selectedWorkflowID }) ?? workflows.first ?? .readOnly
  }

  init() {}

  init(from decoder: Decoder) throws {
    self.init()
    let values = try decoder.container(keyedBy: CodingKeys.self)
    version = try values.decodeIfPresent(Int.self, forKey: .version) ?? version
    codexPath = try values.decodeIfPresent(String.self, forKey: .codexPath) ?? codexPath
    agentpermPath = try values.decodeIfPresent(String.self, forKey: .agentpermPath) ?? agentpermPath
    codexProfile = try values.decodeIfPresent(String.self, forKey: .codexProfile) ?? codexProfile
    codexModel = try values.decodeIfPresent(String.self, forKey: .codexModel) ?? codexModel
    repositoryRoots =
      try values.decodeIfPresent([String].self, forKey: .repositoryRoots) ?? repositoryRoots
    repositoryExclusions =
      try values.decodeIfPresent([String].self, forKey: .repositoryExclusions)
      ?? repositoryExclusions
    globalInstructions =
      try values.decodeIfPresent(String.self, forKey: .globalInstructions) ?? globalInstructions
    workflows = try values.decodeIfPresent([ReviewWorkflow].self, forKey: .workflows) ?? workflows
    selectedWorkflowID =
      try values.decodeIfPresent(UUID.self, forKey: .selectedWorkflowID) ?? selectedWorkflowID
  }
}

enum SettingsStore {
  static let directory = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/Agentperm Config")
  static let path = directory.appendingPathComponent("settings.json")

  static func load() -> AppSettings {
    guard let data = try? Data(contentsOf: path),
      let settings = try? JSONDecoder().decode(AppSettings.self, from: data),
      !settings.workflows.isEmpty
    else { return AppSettings() }
    return settings
  }

  static func save(_ settings: AppSettings) throws {
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(settings).write(to: path, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
  }
}
