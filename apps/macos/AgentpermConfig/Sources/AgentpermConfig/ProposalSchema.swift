import Foundation

enum ProposalSchema {
  static let json = #"""
    {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "summary": {"type": "string"},
        "safety": {"type": "string", "enum": ["read_only", "mixed", "uncertain"]},
        "complete_command_will_be_allowed": {"type": "boolean"},
        "rules": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "id": {"type": "string"},
              "rule": {"type": "string"},
              "decision": {"type": "string", "enum": ["allow", "ask", "deny"]},
              "rationale": {"type": "string"},
              "global_target": {"type": "string"},
              "candidate_project_targets": {"type": "array", "items": {"type": "string"}},
              "selected_targets": {"type": "array", "items": {"type": "string"}},
              "allow_examples": {"type": "array", "items": {"type": "string"}},
              "reject_examples": {"type": "array", "items": {"type": "string"}},
              "replaces": {"type": "array", "items": {"type": "string"}},
              "selected": {"type": "boolean"}
            },
            "required": ["id", "rule", "decision", "rationale", "global_target", "candidate_project_targets", "selected_targets", "allow_examples", "reject_examples", "replaces", "selected"]
          }
        },
        "rejected_parts": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "segment": {"type": "string"},
              "reason": {"type": "string"}
            },
            "required": ["segment", "reason"]
          }
        },
        "notes": {"type": "array", "items": {"type": "string"}}
      },
      "required": ["summary", "safety", "complete_command_will_be_allowed", "rules", "rejected_parts", "notes"]
    }
    """#
}
