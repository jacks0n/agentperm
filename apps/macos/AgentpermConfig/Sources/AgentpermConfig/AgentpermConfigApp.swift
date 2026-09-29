import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }

  func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool { true }

  func applicationWillTerminate(_: Notification) {
    ProcessRegistry.shared.terminateAll()
  }
}

@main
struct AgentpermConfigApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
  @StateObject private var model: AppModel

  init() {
    let arguments = ProcessInfo.processInfo.arguments
    let command: String?
    if let index = arguments.firstIndex(of: "--command"), arguments.indices.contains(index + 1) {
      command = arguments[index + 1]
    } else {
      command = nil
    }
    _model = StateObject(wrappedValue: AppModel(command: command))
  }

  var body: some Scene {
    Window("Agentperm Config", id: "main") {
      ContentView(model: model)
        .frame(minWidth: 980, idealWidth: 1180, minHeight: 680, idealHeight: 780)
        .onAppear { model.start() }
        .onOpenURL { model.accept(url: $0) }
    }
    .windowStyle(.titleBar)
    .commands {
      CommandGroup(replacing: .newItem) {}
    }

    Settings {
      SettingsView(model: model)
        .frame(width: 720, height: 680)
    }
  }
}
