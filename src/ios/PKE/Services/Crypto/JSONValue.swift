import Foundation

public enum JSONValue: Equatable {
    case string(String)
    case integer(Int64)
    case bool(Bool)
    case null
    case array([JSONValue])
    case object([String: JSONValue])
}
