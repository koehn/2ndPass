import XCTest

@MainActor final class MopUITests: XCTestCase {
    override func setUp() {
        super.setUp()
        XCUIDevice.shared.orientation = .portrait
    }
    private func launch() -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launch()
        return app
    }
    private func openItems(_ app: XCUIApplication) {
        let item = app.staticTexts["Example Login"].firstMatch
        if !item.waitForExistence(timeout: 3) {
            let sidebar = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'sidebar'")).firstMatch
            if sidebar.exists { sidebar.tap() }
            let all = app.staticTexts["All Items"].firstMatch
            XCTAssertTrue(all.waitForExistence(timeout: 10))
            all.tap()
        }
        XCTAssertTrue(item.waitForExistence(timeout: 10))
    }
    func testOTPDisplaysCodeAndValidatesReplacementWithoutRevealingSeed() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_OTP_TEST"] = "1"
        app.launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let code = app.staticTexts.matching(NSPredicate(format: "identifier BEGINSWITH 'otp-code-'")).firstMatch
        XCTAssertTrue(code.waitForExistence(timeout: 5))
        let numeric = NSPredicate(format: "label MATCHES '[0-9]{6}'")
        expectation(for: numeric, evaluatedWith: code)
        waitForExpectations(timeout: 5)
        XCTAssertFalse(app.staticTexts["JBSWY3DPEHPK3PXP"].exists)
        app.buttons["Actions for otp"].tap()
        XCTAssertFalse(app.buttons["Reveal"].exists)
        XCTAssertTrue(app.buttons["Copy value"].exists)
        app.buttons["Edit value"].tap()
        let field = app.secureTextFields["otp value"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        XCTAssertEqual(field.value as? String, field.placeholderValue ?? "")
        field.tap(); field.typeText("123456")
        XCTAssertFalse(app.buttons["Save"].isEnabled)
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'Enter a valid Base32 secret'")).firstMatch.exists)
        app.buttons["Cancel"].tap()
        app.buttons["Actions for otp"].tap()
        app.buttons["Edit value"].tap()
        let replacement = app.secureTextFields["otp value"]
        XCTAssertTrue(replacement.waitForExistence(timeout: 5))
        replacement.tap(); replacement.typeText("JBSWY3DPEHPK3PXP")
        XCTAssertEqual((replacement.value as? String)?.count, 16, "Replacement character count")
        let enabled = NSPredicate(format: "enabled == true")
        expectation(for: enabled, evaluatedWith: app.buttons["Save"])
        waitForExpectations(timeout: 5)
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "OTP replacement validation"; screenshot.lifetime = .keepAlways
        add(screenshot)
    }

    func testOTPSeedAndURLBothDisplayCodes() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_OTP_TEST"] = "1"
        app.launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let seed = app.staticTexts["otp-code-mop://personal/Example%20Login/otp"]
        let url = app.staticTexts["otp-code-mop://personal/Example%20Login/otp-url"]
        XCTAssertTrue(seed.waitForExistence(timeout: 5))
        XCTAssertTrue(url.waitForExistence(timeout: 5))
        let numeric = NSPredicate(format: "label MATCHES '[0-9]{6}'")
        expectation(for: numeric, evaluatedWith: seed)
        expectation(for: numeric, evaluatedWith: url)
        waitForExpectations(timeout: 5)
        XCTAssertEqual(seed.label, url.label)
        let timer = app.descendants(matching: .any)["otp-countdown-mop://personal/Example%20Login/otp-url"].firstMatch
        XCTAssertTrue(timer.waitForExistence(timeout: 5))
        XCTAssertTrue(timer.label.hasPrefix("Code expires in "))
        let legacyActions = app.buttons["Actions for otp-legacy"]
        if !legacyActions.isHittable { app.scrollViews["Item detail"].swipeUp() }
        legacyActions.tap()
        XCTAssertTrue(app.buttons["Reveal"].exists)
        XCTAssertFalse(app.buttons["Use as OTP"].exists)
    }

    func testSearchMenuShowsMatchedFieldAndOpensItem() {
        let app = launch()
        openItems(app)
        let search = app.textFields["Search items"]
        XCTAssertTrue(search.waitForExistence(timeout: 5))
        search.tap(); search.typeText("sample@example.test")
        let result = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'search-result-'")).firstMatch
        XCTAssertTrue(result.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["username: sample@example.test"].exists)
        let menuImage = XCTAttachment(screenshot: app.screenshot())
        menuImage.name = "Search results menu"; menuImage.lifetime = .keepAlways
        add(menuImage)
        result.tap()
        XCTAssertTrue(app.buttons["Edit item"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["sample@example.test"].firstMatch.exists)
        XCTAssertFalse(result.exists)
    }

    func testSearchMenuUpdatesWhenMatchesChange() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_SEARCH_TEST"] = "1"
        app.launch()
        openItems(app)
        let search = app.textFields["Search items"]
        search.tap(); search.typeText("s")
        let example = app.buttons["search-result-00000000-0000-0000-0000-000000000001:Example Login"]
        XCTAssertTrue(example.waitForExistence(timeout: 5))
        search.typeText("s")
        let server = app.buttons["search-result-00000000-0000-0000-0000-000000000001:SSH Server"]
        XCTAssertTrue(server.waitForExistence(timeout: 5))
        XCTAssertFalse(example.exists)
        XCTAssertTrue(app.staticTexts["ssh username: sshd"].exists)
        search.typeText("h")
        XCTAssertTrue(server.exists)
        XCTAssertTrue(app.staticTexts["ssh username: sshd"].exists)
        server.tap()
        XCTAssertTrue(app.buttons["Edit item"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["sshd"].firstMatch.exists)
    }

    func testCopyFeedbackAppearsOverFieldAndDisappears() {
        let app = launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let value = app.descendants(matching: .any)["sample@example.test"].firstMatch
        XCTAssertTrue(value.waitForExistence(timeout: 5))
        value.tap()
        let feedback = app.descendants(matching: .any)["copy-feedback-username"].firstMatch
        XCTAssertTrue(feedback.waitForExistence(timeout: 2))
        XCTAssertLessThan(abs(feedback.frame.midY - value.frame.midY), 70)
        XCTAssertTrue(feedback.waitForNonExistence(timeout: 4))
        XCTAssertFalse(app.staticTexts["Value copied."].exists)
    }

    func testVaultSettingsAndFieldActions() {
        let app = launch()
        let settings = app.buttons["Settings for personal"].firstMatch
        if !settings.waitForExistence(timeout: 3) || !settings.isHittable {
            let sidebar = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'sidebar'")).firstMatch
            if sidebar.exists { sidebar.tap() }
            else if app.buttons["Back"].exists { app.buttons["Back"].tap() }
        }
        XCTAssertTrue(settings.waitForExistence(timeout: 5))
        settings.tap()
        XCTAssertTrue(app.staticTexts["Vault Settings"].waitForExistence(timeout: 5))
        let settingsImage = XCTAttachment(screenshot: app.screenshot())
        settingsImage.name = "Vault Settings"
        settingsImage.lifetime = .keepAlways
        add(settingsImage)
        XCTAssertTrue(app.buttons["Export encrypted backup…"].exists)
        app.buttons["Recover access…"].tap()
        XCTAssertTrue(app.staticTexts["Recover vault access"].waitForExistence(timeout: 5))
        app.buttons["Cancel"].tap()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let actions = app.buttons["Actions for password"]
        XCTAssertTrue(actions.waitForExistence(timeout: 5))
        let detailImage = XCTAttachment(screenshot: app.screenshot())
        detailImage.name = "Item detail"
        detailImage.lifetime = .keepAlways
        add(detailImage)
        actions.tap()
        XCTAssertTrue(app.buttons["Reveal"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Copy value"].exists)
        app.buttons["Reveal"].tap()
        actions.tap()
        XCTAssertTrue(app.buttons["Conceal"].waitForExistence(timeout: 5))
        app.buttons["Conceal"].tap()
        XCTAssertTrue(actions.waitForExistence(timeout: 5))
    }

    func testDetailHeaderAndInlineFieldActions() {
        let app = launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let edit = app.buttons["Edit item"]
        XCTAssertTrue(edit.waitForExistence(timeout: 5))
        let settings = app.buttons["Settings"].firstMatch
        XCTAssertGreaterThanOrEqual(edit.frame.minY, settings.frame.maxY)
        let value = app.staticTexts["sample@example.test"].firstMatch
        XCTAssertFalse(app.buttons["Copy username value"].exists)
        XCTAssertFalse(app.buttons["Reveal password"].exists)
        let menu = app.buttons["Actions for username"]
        XCTAssertTrue(menu.exists)
        XCTAssertGreaterThan(menu.frame.minX, value.frame.minX)
        XCTAssertEqual(menu.frame.midY, value.frame.midY, accuracy: 2)
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "Mobile inline fields"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }

    func testBrowseEditGenerateAndLock() {
        let app = launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        XCTAssertTrue(app.buttons["Edit item"].waitForExistence(timeout: 5))
        app.buttons["Edit item"].tap()
        let generator = app.buttons["Generate password"].firstMatch
        let detail = app.scrollViews["Item detail"]
        for _ in 0..<4 {
            if generator.exists && generator.isHittable { break }
            detail.swipeUp()
        }
        XCTAssertTrue(generator.waitForExistence(timeout: 5), app.debugDescription)
        generator.tap()
        XCTAssertTrue(app.buttons["Use password"].waitForExistence(timeout: 5))
        app.buttons["Use password"].tap()
        for _ in 0..<4 {
            if app.buttons["Save"].isHittable { break }
            detail.swipeDown()
        }
        app.buttons["Save"].tap()
        XCTAssertTrue(app.buttons["Edit item"].waitForExistence(timeout: 5))
        app.buttons["Lock"].tap()
        XCTAssertFalse(app.textFields["password value"].exists)
        XCTAssertFalse(app.staticTexts["sample@example.test"].exists)
    }
    func testCreateAndAdaptToRotation() {
        let app = launch()
        openItems(app)
        app.buttons["New item"].tap()
        let name = app.textFields["Item name"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.tap()
        name.typeText("Created in UI")
        XCUIDevice.shared.orientation = .landscapeLeft
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        XCTAssertEqual(name.value as? String, "Created in UI")
        XCUIDevice.shared.orientation = .portrait
        let detail = app.scrollViews["Item detail"]
        for _ in 0..<4 {
            if app.buttons["Save"].isHittable { break }
            detail.swipeDown()
        }
        app.buttons["Save"].tap()
        XCTAssertTrue(app.buttons["Edit item"].waitForExistence(timeout: 5))
        XCUIDevice.shared.orientation = .portrait
    }
    func testTrustFailureDoesNotAutomaticallyRetry() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_VAULT_TRUST_FAILURE"] = "1"
        app.launch()
        let alert = app.alerts["Operation not completed"]
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        alert.buttons["OK"].tap()
        app.buttons["Settings"].firstMatch.tap()
        XCTAssertTrue(app.steppers.firstMatch.waitForExistence(timeout: 5))
        app.buttons["Done"].tap()
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertFalse(alert.waitForExistence(timeout: 3))
    }
    func testSettingsAndTemporarySystemInterruption() {
        let app = launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        XCTAssertTrue(app.buttons["Settings"].waitForExistence(timeout: 10))
        app.buttons["Settings"].tap()
        XCTAssertTrue(app.steppers.firstMatch.waitForExistence(timeout: 5))
        app.buttons["Done"].tap()
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.staticTexts["sample@example.test"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Edit item"].exists)
        XCTAssertFalse(app.buttons["Unlock"].exists)
    }
    func testAccessibilityTextSizeKeepsEditingReachable() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchArguments = ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"]
        app.launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let edit = app.buttons["Edit item"]
        XCTAssertTrue(edit.waitForExistence(timeout: 5))
        XCTAssertTrue(edit.isHittable)
        edit.tap()
        XCTAssertTrue(app.buttons["Cancel"].waitForExistence(timeout: 5))
        app.buttons["Cancel"].tap()
        XCTAssertTrue(edit.waitForExistence(timeout: 5))
    }

}

extension MopUITests {
    func testLegacyPairingIsAbsent() {
        let app = launch()
        XCTAssertFalse(app.buttons["Scan pairing QR"].exists)
        XCTAssertFalse(app.buttons["Add mobile device"].exists)
    }
}

extension MopUITests {
    func testWaitingForIdentityDoesNotRetryAuthentication() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_IDENTITY_PENDING"] = "1"
        app.launch()
        let alert = app.alerts["Operation not completed"]
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        XCTAssertTrue(alert.staticTexts.matching(NSPredicate(format: "label CONTAINS 'Waiting for your Mop identity'")).firstMatch.exists)
        alert.buttons["OK"].tap()
        app.buttons["Settings"].firstMatch.tap()
        app.buttons["Done"].tap()
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertFalse(alert.waitForExistence(timeout: 3))
    }
}
