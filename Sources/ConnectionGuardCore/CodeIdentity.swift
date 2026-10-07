import Foundation
import Security

public enum CodeIdentity {
    private static func metadata(_ code: SecStaticCode) throws -> [String: Any] {
        guard SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess else {
            throw GuardError.invalid("Подпись программы недействительна. Выберите установленную подписанную программу.")
        }
        var information: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(code, flags, &information) == errSecSuccess,
              let info = information as? [String: Any] else { throw GuardError.invalid("Не удалось прочитать подпись.") }
        return info
    }
    private static func fields(_ info: [String: Any]) throws -> (String, String?, String) {
        guard let identifier = info[kSecCodeInfoIdentifier as String] as? String,
              let hash = info[kSecCodeInfoUnique as String] as? Data, !hash.isEmpty else {
            throw GuardError.invalid("У программы нет проверяемой идентификации кода.")
        }
        return (identifier, info[kSecCodeInfoTeamIdentifier as String] as? String,
                hash.map { String(format: "%02x", $0) }.joined())
    }
    public static func enroll(url: URL, kind: TargetKind) throws -> ProgramTarget {
        let canonical = url.resolvingSymlinksInPath().standardizedFileURL
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(canonical as CFURL, [], &code) == errSecSuccess, let code else {
            throw GuardError.invalid("Не удалось прочитать выбранную программу.")
        }
        let (identifier, team, hash) = try fields(metadata(code))
        let target = ProgramTarget(kind: kind, path: canonical.path, signingIdentifier: identifier,
                                   teamIdentifier: team, codeHash: hash)
        try target.validate()
        return target
    }
    public static func resolve(auditToken: Data) throws -> VerifiedProcess {
        // audit_token_t is eight uint32 values. Never resolve through a racy PID lookup.
        guard auditToken.count == 32 else { throw GuardError.invalid("Нет audit token процесса.") }
        let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, [], nil) == errSecSuccess else {
            throw GuardError.invalid("Не удалось подтвердить запущенный процесс.")
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw GuardError.invalid("Не удалось получить подпись процесса.")
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let executable = info[kSecCodeInfoMainExecutable as String] as? URL else {
            throw GuardError.invalid("Нет идентификации исполняемого файла.")
        }
        let (identifier, team, hash) = try fields(info)
        return VerifiedProcess(executablePath: executable.resolvingSymlinksInPath().standardizedFileURL.path,
                               signingIdentifier: identifier, teamIdentifier: team, codeHash: hash)
    }
}
