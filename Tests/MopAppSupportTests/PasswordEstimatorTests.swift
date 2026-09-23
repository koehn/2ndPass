import Testing
import MopCore
import MopAppSupport

struct PasswordEstimatorTests {
    @Test func recognizesCommonPasswordsAndRepetition() {
        for password in ["", "password", "Password1!", "12345678", "qwerty", String(repeating: "abc", count: 40)] {
            #expect(PasswordEstimator.estimate(password).rawValue <= PasswordQuality.weak.rawValue)
        }
    }
    @Test func recognizesGeneratedPasswordAndUsesUserInputs() {
        #expect(PasswordEstimator.estimate("g8#Qx2!Wm7@Lp9$Rv4").rawValue >= PasswordQuality.strong.rawValue)
        #expect(PasswordEstimator.estimate("MarigoldEngineering", userInputs: ["MarigoldEngineering"]).rawValue <= PasswordQuality.weak.rawValue)
    }
    @Test func unicodeAndLongInputsRemainBounded() {
        _ = PasswordEstimator.estimate("登录🔑 ééß ゆき☃️")
        #expect(PasswordEstimator.estimate(String(repeating: "a", count: 10_000)) == .veryWeak)
    }
}
