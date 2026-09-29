import Foundation

enum RepositoryDiscovery {
  private static let manifestNames = Set([
    "justfile", "Justfile", "Makefile", "makefile", "package.json", "pyproject.toml", "mise.toml",
  ])
  private static let skippedDirectories = Set([
    "node_modules", ".venv", "venv", "target", "cdk.out", ".next", "dist", "build", ".build",
    "DerivedData",
    ".cache", ".terraform", "coverage", "Library", ".Trash", "Applications", ".npm", ".cargo",
    ".rustup", ".gradle", ".local", ".pyenv", ".nvm", ".bun", "Desktop", "Documents",
    "Downloads", "Movies", "Music", "Pictures",
  ])

  static func homeDiscoveryRoots(additionalRoots: [String]) -> [String] {
    let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
    let explicitExceptions = additionalRoots.filter { root in
      let path = URL(
        fileURLWithPath: NSString(string: root).expandingTildeInPath
      ).standardizedFileURL.path
      guard path.hasPrefix("\(home)/") else { return path != home }
      let components = path.dropFirst(home.count + 1).split(separator: "/").map(String.init)
      return components.contains { $0.hasPrefix(".") || skippedDirectories.contains($0) }
    }
    return ["~"] + explicitExceptions
  }

  static func discover(
    for command: String,
    roots: [String] = ["~/Code"],
    exclusions: [String] = []
  ) async -> [RepositoryContext] {
    await Task.detached(priority: .utility) {
      let repositories = Set(
        roots.flatMap { root -> [URL] in
          let expanded = NSString(string: root).expandingTildeInPath
          return scanRepositories(root: URL(fileURLWithPath: expanded), exclusions: Set(exclusions))
        })
      return
        repositories
        .map { context(for: $0, command: command) }
        .sorted {
          if $0.score == $1.score {
            return $0.path.localizedStandardCompare($1.path) == .orderedAscending
          }
          return $0.score > $1.score
        }
    }.value
  }

  private static func scanRepositories(root: URL, exclusions: Set<String>) -> [URL] {
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory),
      isDirectory.boolValue
    else { return [] }
    guard
      let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey],
        options: [.skipsPackageDescendants],
        errorHandler: { _, _ in true }
      )
    else { return [] }

    var repositories = Set<URL>()
    while let item = enumerator.nextObject() as? URL {
      let name = item.lastPathComponent
      if name == ".git" {
        repositories.insert(item.deletingLastPathComponent().standardizedFileURL)
        if (try? item.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
          enumerator.skipDescendants()
        }
        continue
      }
      if name.hasPrefix(".") {
        enumerator.skipDescendants()
        continue
      }
      if skippedDirectories.union(exclusions).contains(name) {
        enumerator.skipDescendants()
        continue
      }
    }
    return repositories.sorted { $0.path.localizedStandardCompare($1.path) == .orderedAscending }
  }

  private static func context(for repository: URL, command: String) -> RepositoryContext {
    var evidenceParts: [String] = []
    for name in manifestNames {
      let manifest = repository.appendingPathComponent(name)
      guard let data = try? Data(contentsOf: manifest, options: [.mappedIfSafe]), !data.isEmpty
      else { continue }
      let prefix = data.prefix(120_000)
      let text = String(decoding: prefix, as: UTF8.self)
      evidenceParts.append("## \(name)\n\(summariseManifest(name: name, text: text))")
    }

    let evidence = evidenceParts.joined(separator: "\n")
    let loweredCommand = command.lowercased()
    let tokens = loweredCommand.split { !$0.isLetter && !$0.isNumber && $0 != "-" && $0 != "_" }
      .map(String.init)
      .filter { $0.count >= 3 }
    let loweredEvidence = evidence.lowercased()
    var score = tokens.reduce(0) { $0 + (loweredEvidence.contains($1) ? 3 : 0) }
    if loweredCommand.contains(repository.path.lowercased()) { score += 100 }
    if loweredCommand.contains(repository.lastPathComponent.lowercased()) { score += 20 }
    if FileManager.default.fileExists(
      atPath: repository.appendingPathComponent(".agent-permissions.jsonc").path)
    {
      score += 1
    }
    return RepositoryContext(
      path: repository.path,
      name: repository.lastPathComponent,
      evidence: String(evidence.prefix(12_000)),
      score: score
    )
  }

  private static func summariseManifest(name: String, text: String) -> String {
    if name == "package.json",
      let data = text.data(using: .utf8),
      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
      let scripts = object["scripts"] as? [String: Any]
    {
      return scripts.keys.sorted().map { "script: \($0)" }.joined(separator: "\n")
    }
    if name.lowercased() == "justfile" {
      return text.split(separator: "\n")
        .filter { line in
          guard let first = line.first, first != " ", first != "\t", first != "#" else {
            return false
          }
          return line.contains(":")
        }
        .prefix(200)
        .map(String.init)
        .joined(separator: "\n")
    }
    if name.lowercased() == "makefile" {
      return text.split(separator: "\n")
        .filter { line in
          guard let first = line.first, first != " ", first != "\t", first != "#",
            !line.contains(Character("="))
          else {
            return false
          }
          return line.contains(":")
        }
        .prefix(200)
        .map(String.init)
        .joined(separator: "\n")
    }
    return text.split(separator: "\n")
      .filter { line in
        let value = line.lowercased()
        return value.contains("script") || value.contains("tool.") || value.contains("task")
      }
      .prefix(120)
      .map(String.init)
      .joined(separator: "\n")
  }
}
