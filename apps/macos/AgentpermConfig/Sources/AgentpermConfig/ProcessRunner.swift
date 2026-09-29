import Foundation

struct ProcessOutput: Sendable {
  let status: Int32
  let stdout: String
  let stderr: String
}

enum ProcessRunner {
  static func run(
    executable: String,
    arguments: [String],
    input: String? = nil,
    currentDirectory: String? = nil,
    timeoutSeconds: Double? = nil
  ) async throws -> ProcessOutput {
    if let timeoutSeconds {
      return try await withThrowingTaskGroup(of: ProcessOutput.self) { group in
        group.addTask {
          try await run(
            executable: executable,
            arguments: arguments,
            input: input,
            currentDirectory: currentDirectory
          )
        }
        group.addTask {
          try await Task.sleep(for: .seconds(timeoutSeconds))
          throw ReviewError.message(
            "\(URL(fileURLWithPath: executable).lastPathComponent) timed out after \(Int(timeoutSeconds)) seconds"
          )
        }
        guard let first = try await group.next() else {
          throw ReviewError.message("Process did not produce a result")
        }
        group.cancelAll()
        return first
      }
    }
    let box = ProcessBox()
    return try await withTaskCancellationHandler {
      try await Task.detached(priority: .userInitiated) {
        let process = box.process
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let currentDirectory {
          process.currentDirectoryURL = URL(fileURLWithPath: currentDirectory)
        }

        process.environment = ProcessInfo.processInfo.environment

        let stdout = Pipe()
        let stderr = Pipe()
        let stdoutBuffer = LockedData()
        let stderrBuffer = LockedData()
        stdout.fileHandleForReading.readabilityHandler = { handle in
          let data = handle.availableData
          if !data.isEmpty { stdoutBuffer.append(data) }
        }
        stderr.fileHandleForReading.readabilityHandler = { handle in
          let data = handle.availableData
          if !data.isEmpty { stderrBuffer.append(data) }
        }
        process.standardOutput = stdout
        process.standardError = stderr

        var stdin: Pipe?
        if input != nil {
          let pipe = Pipe()
          process.standardInput = pipe
          stdin = pipe
        }

        try process.run()
        ProcessRegistry.shared.register(process)
        if let input, let data = input.data(using: .utf8) {
          stdin?.fileHandleForWriting.write(data)
          try? stdin?.fileHandleForWriting.close()
        }

        process.waitUntilExit()
        ProcessRegistry.shared.unregister(process)
        stdout.fileHandleForReading.readabilityHandler = nil
        stderr.fileHandleForReading.readabilityHandler = nil
        stdoutBuffer.append(stdout.fileHandleForReading.readDataToEndOfFile())
        stderrBuffer.append(stderr.fileHandleForReading.readDataToEndOfFile())
        return ProcessOutput(
          status: process.terminationStatus,
          stdout: String(decoding: stdoutBuffer.value, as: UTF8.self),
          stderr: String(decoding: stderrBuffer.value, as: UTF8.self)
        )
      }.value
    } onCancel: {
      box.terminate()
    }
  }

  static func locate(_ name: String) -> String? {
    let path = ProcessInfo.processInfo.environment["PATH"] ?? ""
    let candidates = path.split(separator: ":").map {
      URL(fileURLWithPath: String($0)).appendingPathComponent(name).path
    }
    return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
  }

  static func executable(
    named name: String,
    override: String,
    environmentFallback: String? = nil
  ) -> String? {
    let configured = NSString(string: override).expandingTildeInPath
    if !override.isEmpty {
      return FileManager.default.isExecutableFile(atPath: configured) ? configured : nil
    }
    if let located = locate(name) { return located }
    guard let environmentFallback else { return nil }
    let fallback = NSString(string: environmentFallback).expandingTildeInPath
    return FileManager.default.isExecutableFile(atPath: fallback) ? fallback : nil
  }
}

private final class ProcessBox: @unchecked Sendable {
  let process = Process()

  func terminate() {
    if process.isRunning { process.terminate() }
  }
}

private final class LockedData: @unchecked Sendable {
  private let lock = NSLock()
  private var data = Data()

  func append(_ addition: Data) {
    lock.lock()
    data.append(addition)
    lock.unlock()
  }

  var value: Data {
    lock.lock()
    defer { lock.unlock() }
    return data
  }
}

final class ProcessRegistry: @unchecked Sendable {
  static let shared = ProcessRegistry()
  private let lock = NSLock()
  private var processes: [ObjectIdentifier: Process] = [:]

  func register(_ process: Process) {
    lock.lock()
    processes[ObjectIdentifier(process)] = process
    lock.unlock()
  }

  func unregister(_ process: Process) {
    lock.lock()
    processes.removeValue(forKey: ObjectIdentifier(process))
    lock.unlock()
  }

  func terminateAll() {
    lock.lock()
    let running = Array(processes.values)
    processes.removeAll()
    lock.unlock()
    for process in running where process.isRunning { process.terminate() }
  }
}
