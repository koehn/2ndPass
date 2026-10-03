import XCTest

#if os(iOS)

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
    func testSecurityFindingAndConcealedHistory() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_SECURITY_TEST"] = "1"
        app.launch()
        let security = app.staticTexts["Security"].firstMatch
        if !app.buttons["Check Now"].waitForExistence(timeout: 5), security.exists { security.tap() }
        XCTAssertTrue(app.buttons["Check Now"].waitForExistence(timeout: 10))
        let finding = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'security-finding-'")).firstMatch
        for _ in 0..<5 {
            if finding.exists && finding.isHittable { break }
            let list = app.collectionViews["security-health-list"]
            if list.exists { list.swipeUp() } else { app.swipeUp() }
        }
        XCTAssertTrue(finding.waitForExistence(timeout: 10))
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = "Security health findings"; shot.lifetime = .keepAlways; add(shot)
        finding.tap()
        let actions = app.buttons["Actions for password"]
        XCTAssertTrue(actions.waitForExistence(timeout: 5)); actions.tap()
        app.buttons["View History"].tap()
        XCTAssertTrue(app.staticTexts["Secret History"].firstMatch.waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["previous-ui-password"].exists)
        app.buttons["Reveal"].firstMatch.tap()
        XCTAssertTrue(app.staticTexts["previous-ui-password"].waitForExistence(timeout: 5))
        app.buttons["Conceal"].firstMatch.tap()
        XCTAssertFalse(app.staticTexts["previous-ui-password"].exists)
        let history = XCTAttachment(screenshot: app.screenshot())
        history.name = "Concealed secret history"; history.lifetime = .keepAlways; add(history)
        app.buttons["Done"].firstMatch.tap()
    }

    func testTypingSearchDoesNotNavigateOrDismissKeyboard() {
        let app = launch()
        openItems(app)
        let search = app.textFields["Item search"]
        search.tap()
        typeReliably("Example", into: search)
        XCTAssertTrue(search.isHittable)
        XCTAssertEqual(search.value as? String, "Example")
        XCTAssertTrue(app.keyboards.firstMatch.exists)
        typeReliably(" missing", into: search)
        XCTAssertTrue(search.isHittable)
        XCTAssertTrue(app.keyboards.firstMatch.exists)
        app.buttons["Clear Search"].firstMatch.tap()
        typeReliably("Example", into: search)
        search.typeText("\n")
        XCTAssertTrue(app.buttons["Edit"].waitForExistence(timeout: 5))
    }
    func testKeyCreationRequiresExplicitStorageAndImportsResetSelection() {
        let app = launch()
        openItems(app)
        app.buttons["New"].firstMatch.tap()
        app.buttons["New SSH Key…"].tap()
        let save = app.buttons["key-save"]
        XCTAssertTrue(save.waitForExistence(timeout: 5))
        XCTAssertFalse(save.isEnabled)
        let name = app.textFields["key-name"]
        name.tap(); typeReliably("SSH test", into: name)
        XCTAssertFalse(save.isEnabled, "Naming a key must not silently choose cloud or hardware storage")
        app.buttons["key-storage"].tap()
        let personal = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'personal'")).firstMatch
        XCTAssertTrue(personal.waitForExistence(timeout: 5)); personal.tap()
        XCTAssertTrue(save.isEnabled)
        app.segmentedControls["key-source"].buttons["Import"].tap()
        XCTAssertTrue(app.buttons["Choose OpenSSH File…"].waitForExistence(timeout: 5))
        XCTAssertFalse(save.isEnabled, "Import requires an explicit cloud destination and file")
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "Explicit key storage and import"; screenshot.lifetime = .keepAlways
        add(screenshot)
        app.buttons["Cancel"].tap()
    }
    func testEnrollmentWaitsWithoutSpinnerAndCanClose() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_ENROLLMENT"] = "1"
        app.launch()
        XCTAssertTrue(app.buttons["Connect"].waitForExistence(timeout: 10))
        app.buttons["Connect"].tap()
        let waiting = app.staticTexts["Open and unlock 2ndPass on another connected device."]
        XCTAssertTrue(waiting.waitForExistence(timeout: 5))
        XCTAssertFalse(app.activityIndicators.firstMatch.exists)
        app.buttons["Close"].tap()
        XCTAssertFalse(waiting.exists)
    }
    private func typeReliably(_ text: String, into field: XCUIElement) {
        // Synchronize key events with SwiftUI relayout; batched simulator input
        // can drop characters in both the title editor and secure fields.
        for character in text { field.typeText(String(character)) }
    }
    private func dismissSidebar(_ app: XCUIApplication) {
        // iPad can present the sidebar as an overlay after rotation or a sheet.
        // Its dismissal consumes a tap that would otherwise target the detail.
        if app.collectionViews["Sidebar"].exists && app.collectionViews["Sidebar"].isHittable {
            let toggle = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'sidebar'")).firstMatch
            if toggle.exists { toggle.tap() }
        }
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
        dismissSidebar(app)
    }
    func testOTPDisplaysCodeAndValidatesReplacementWithoutRevealingSeed() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_OTP_TEST"] = "1"
        app.launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let code = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'otp-code-'")).firstMatch
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
        field.tap(); typeReliably("123456", into: field)
        XCTAssertFalse(app.buttons["Save"].isEnabled)
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'Enter a valid Base32 secret'")).firstMatch.exists)
        app.buttons["Cancel"].tap()
        app.buttons["Actions for otp"].tap()
        app.buttons["Edit value"].tap()
        let replacement = app.secureTextFields["otp value"]
        XCTAssertTrue(replacement.waitForExistence(timeout: 5))
        replacement.tap(); typeReliably("JBSWY3DPEHPK3PXP", into: replacement)
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
        let seed = app.descendants(matching: .any)["otp-code-sp://personal/Example%20Login/otp"].firstMatch
        let url = app.descendants(matching: .any)["otp-code-sp://personal/Example%20Login/otp-url"].firstMatch
        XCTAssertTrue(seed.waitForExistence(timeout: 5))
        XCTAssertTrue(url.waitForExistence(timeout: 5))
        let numeric = NSPredicate(format: "label MATCHES '[0-9]{6}'")
        expectation(for: numeric, evaluatedWith: seed)
        expectation(for: numeric, evaluatedWith: url)
        waitForExpectations(timeout: 5)
        XCTAssertEqual(seed.label, url.label)
        let timer = app.descendants(matching: .any)["otp-countdown-sp://personal/Example%20Login/otp-url"].firstMatch
        XCTAssertTrue(timer.waitForExistence(timeout: 5))
        XCTAssertTrue(timer.label.hasPrefix("Code expires in "))
        let legacyActions = app.buttons["Actions for otp-legacy"]
        if !legacyActions.isHittable { app.scrollViews["Item detail"].swipeUp() }
        legacyActions.tap()
        XCTAssertTrue(app.buttons["Reveal"].exists)
        XCTAssertFalse(app.buttons["Use as OTP"].exists)
    }

    func testRestoresSelectedItemAfterRelaunch() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_SELECTION_TEST"] = UUID().uuidString
        app.launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        XCTAssertTrue(app.buttons["Edit"].waitForExistence(timeout: 5))
        app.terminate()
        app.launch()
        XCTAssertTrue(app.buttons["Edit"].waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(app.buttons["Copy password value"].exists)
        XCTAssertFalse(app.staticTexts["ui-fixture-password"].exists)
    }

    func testRecentVirtualVaults() {
        for title in ["Recently Added", "Recently Changed", "Recently Used"] {
            let app = XCUIApplication()
            app.launchEnvironment["MOP_UI_TESTING"] = "1"
            app.launchEnvironment["MOP_UI_RECENTS_TEST"] = "1"
            app.launch()
            openItems(app)
            app.buttons["BackButton"].tap()
            let link = app.staticTexts[title].firstMatch
            XCTAssertTrue(link.waitForExistence(timeout: 10), app.debugDescription)
            link.tap()
            XCTAssertTrue(app.textFields["Item search"].waitForExistence(timeout: 5))
            if title == "Recently Used" {
                XCTAssertFalse(app.staticTexts["Example Login"].exists)
            } else {
                let item = app.staticTexts["Example Login"].firstMatch
                XCTAssertTrue(item.waitForExistence(timeout: 5))
                item.tap()
                XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Created: '")).firstMatch.waitForExistence(timeout: 5))
            }
            app.terminate()
        }
    }

    func testSearchFiltersListAndOpensItem() {
        let app = launch()
        openItems(app)
        let search = app.textFields["Item search"]
        if !search.exists, app.buttons["Search"].firstMatch.exists { app.buttons["Search"].firstMatch.tap() }
        XCTAssertTrue(search.waitForExistence(timeout: 5), app.debugDescription)
        search.tap(); search.typeText("sample@example.test")
        let result = app.staticTexts["Example Login"].firstMatch
        XCTAssertTrue(result.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["username: sample@example.test"].exists)
        let menuImage = XCTAttachment(screenshot: app.screenshot())
        menuImage.name = "Filtered search results"; menuImage.lifetime = .keepAlways
        add(menuImage)
        result.tap()
        XCTAssertTrue(app.buttons["Edit"].waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertTrue(app.descendants(matching: .any)["sample@example.test"].firstMatch.exists)
        XCTAssertTrue(app.buttons["Copy username value"].exists)
    }

    func testSearchFiltersAsQueryChanges() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_SEARCH_TEST"] = "1"
        app.launch()
        openItems(app)
        let search = app.textFields["Item search"]
        search.tap(); search.typeText("s")
        let example = app.staticTexts["Example Login"].firstMatch
        XCTAssertTrue(example.waitForExistence(timeout: 5))
        search.typeText("s")
        let server = app.staticTexts["SSH Server"].firstMatch
        XCTAssertTrue(server.waitForExistence(timeout: 5))
        XCTAssertTrue(example.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["ssh username: sshd"].exists)
        search.typeText("h")
        XCTAssertTrue(server.exists)
        XCTAssertTrue(app.staticTexts["ssh username: sshd"].exists)
        server.tap()
        XCTAssertTrue(app.buttons["Edit"].waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertTrue(app.descendants(matching: .any)["sshd"].firstMatch.exists)
    }

    func testCopyFeedbackAppearsOverFieldAndDisappears() {
        let app = launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let value = app.descendants(matching: .any)["sample@example.test"].firstMatch
        XCTAssertTrue(value.waitForExistence(timeout: 5))
        app.buttons["Copy username value"].tap()
        let feedback = app.descendants(matching: .any)["copy-feedback-username"].firstMatch
        XCTAssertTrue(feedback.waitForExistence(timeout: 2))
        XCTAssertLessThan(abs(feedback.frame.midY - value.frame.midY), 70)
        XCTAssertTrue(feedback.waitForNonExistence(timeout: 4))
        XCTAssertFalse(app.staticTexts["Value copied."].exists)
    }

    func testVaultSettingsAndFieldActions() {
        let app = launch()
        openItems(app)
        app.buttons["Vault Details"].firstMatch.tap()
        XCTAssertTrue(app.buttons["Export Encrypted Backup…"].waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertTrue(app.buttons["Rename Vault…"].exists)
        let settingsImage = XCTAttachment(screenshot: app.screenshot())
        settingsImage.name = "Vault Details"; settingsImage.lifetime = .keepAlways
        add(settingsImage)
        app.buttons["Back to Items"].tap()
        if app.buttons["Back"].exists { app.buttons["Back"].tap() }
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let actions = app.buttons["Actions for password"]
        XCTAssertTrue(actions.waitForExistence(timeout: 5), app.debugDescription)
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
        XCTAssertTrue(actions.waitForExistence(timeout: 5), app.debugDescription)
    }

    func testDetailHeaderAndInlineFieldActions() {
        let app = launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let edit = app.buttons["Edit"]
        XCTAssertTrue(edit.waitForExistence(timeout: 5))
        let settings = app.buttons["Settings"].firstMatch
        XCTAssertGreaterThanOrEqual(edit.frame.minY, settings.frame.maxY)
        let value = app.staticTexts["sample@example.test"].firstMatch
        XCTAssertTrue(app.buttons["Copy username value"].exists)
        XCTAssertTrue(app.buttons["Reveal password"].exists)
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
        XCTAssertTrue(app.buttons["Edit"].waitForExistence(timeout: 5), app.debugDescription)
        app.buttons["Edit"].tap()
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
        XCTAssertTrue(app.buttons["Edit"].waitForExistence(timeout: 5), app.debugDescription)
        app.buttons["Lock"].tap()
        XCTAssertFalse(app.textFields["password value"].exists)
        XCTAssertFalse(app.staticTexts["sample@example.test"].exists)
    }
    func testCreateAndAdaptToRotation() {
        let app = launch()
        openItems(app)
        app.buttons["New"].firstMatch.tap()
        app.buttons["New Item"].tap()
        let name = app.textFields["Item name"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.tap()
        typeReliably("Created in UI", into: name)
        XCTAssertEqual(name.value as? String, "Created in UI")
        XCUIDevice.shared.orientation = .landscapeLeft
        let landscape = NSPredicate { _, _ in app.frame.width > app.frame.height }
        expectation(for: landscape, evaluatedWith: app)
        waitForExpectations(timeout: 5)
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        XCTAssertEqual(name.value as? String, "Created in UI")
        XCUIDevice.shared.orientation = .portrait
        let portrait = NSPredicate { _, _ in app.frame.height > app.frame.width }
        expectation(for: portrait, evaluatedWith: app)
        waitForExpectations(timeout: 5)
        XCTAssertEqual(name.value as? String, "Created in UI")
        dismissSidebar(app)
        let beforeSave = XCTAttachment(screenshot: app.screenshot())
        beforeSave.name = "Creation after rotation"; beforeSave.lifetime = .keepAlways
        add(beforeSave)
        let detail = app.scrollViews["Item detail"]
        for _ in 0..<4 {
            if app.buttons["Save"].isHittable { break }
            detail.swipeDown()
        }
        app.buttons["Save"].tap()
        XCTAssertTrue(app.buttons["Edit"].waitForExistence(timeout: 5), app.debugDescription)
        XCUIDevice.shared.orientation = .portrait
    }
    func testTrustFailureOffersCancellableRepairOnLockedScreen() {
        let app = XCUIApplication()
        app.launchArguments += ["-icloud-connection-repair-enabled", "YES"]
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_VAULT_TRUST_FAILURE"] = "1"
        app.launch()
        let alert = app.alerts["Operation not completed"]
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        alert.buttons["OK"].tap()
        let repair = app.buttons["Repair iCloud Connection…"]
        XCTAssertTrue(repair.waitForExistence(timeout: 5))
        repair.tap()
        XCTAssertTrue(app.buttons["Reset Connection"].waitForExistence(timeout: 5))
        app.buttons["Cancel"].tap()
        XCTAssertTrue(repair.exists)
        XCTAssertFalse(app.buttons["Reconnect"].exists)
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertFalse(alert.waitForExistence(timeout: 3))
        XCTAssertTrue(repair.exists)
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
        XCTAssertTrue(app.descendants(matching: .any)["inactivity-timeout"].firstMatch.waitForExistence(timeout: 5), app.debugDescription)
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
        XCTAssertTrue(app.descendants(matching: .any)["inactivity-timeout"].firstMatch.waitForExistence(timeout: 5), app.debugDescription)
        app.buttons["Done"].tap()
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.staticTexts["sample@example.test"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Edit"].exists)
        XCTAssertFalse(app.buttons["Unlock"].exists)
    }
    func testAccessibilityTextSizeKeepsEditingReachable() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchArguments = ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"]
        app.launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        let edit = app.buttons["Edit"]
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
        XCTAssertTrue(alert.staticTexts.matching(NSPredicate(format: "label CONTAINS 'no usable enrolled hardware identity'")).firstMatch.exists)
        alert.buttons["OK"].tap()
        app.buttons["Settings"].firstMatch.tap()
        app.buttons["Done"].tap()
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertFalse(alert.waitForExistence(timeout: 3))
    }
}

extension MopUITests {
    func testBackgroundKeepsDraftUntilExplicitLock() {
        let app = launch()
        openItems(app)
        app.staticTexts["Example Login"].firstMatch.tap()
        app.buttons["Edit"].tap()
        let field = app.textFields["username value"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap(); field.typeText("edited")
        let editedValue = field.value as? String
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        XCTAssertEqual(field.value as? String, editedValue)
        XCTAssertTrue(app.secureTextFields["password value"].exists)
        app.buttons["Lock"].firstMatch.tap()
        XCTAssertFalse(field.exists)
        let unlock = app.buttons["Unlock"].firstMatch
        XCTAssertTrue(unlock.waitForExistence(timeout: 5))
        unlock.tap()
        XCTAssertTrue(app.staticTexts["Example Login"].firstMatch.waitForExistence(timeout: 5))
    }
}
#elseif os(macOS)
@MainActor final class MopUITests: XCTestCase {
    private func launch() -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launch()
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Example Login,")).firstMatch.waitForExistence(timeout: 10), app.debugDescription)
        return app
    }
    func testLocalVaultSelectionReplacesCloudItems() {
        let app = launch()
        let local = app.buttons["local"].firstMatch
        XCTAssertTrue(local.waitForExistence(timeout: 5), app.debugDescription)
        local.click()
        XCTAssertTrue(app.staticTexts["Device-only vault"].waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertFalse(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Example Login,")).firstMatch.exists)
        app.buttons["All Items"].click()
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Example Login,")).firstMatch.waitForExistence(timeout: 5))
        local.click()
        XCTAssertTrue(app.staticTexts["Device-only vault"].waitForExistence(timeout: 5))
    }
    private func edit(_ app: XCUIApplication) {
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Example Login,")).firstMatch.click()
        app.buttons["Edit"].click()
        XCTAssertTrue(app.secureTextFields["password value"].waitForExistence(timeout: 5))
    }
    private func changeName(_ app: XCUIApplication) {
        let name = app.textFields["Item name"]
        name.click()
        name.typeKey("a", modifierFlags: .command)
        name.typeText("Changed Login")
    }
    func testEnrollmentWaitsWithoutSpinnerAndCanClose() {
        let app = XCUIApplication()
        app.launchEnvironment["MOP_UI_TESTING"] = "1"
        app.launchEnvironment["MOP_UI_ENROLLMENT"] = "1"
        app.launch()
        XCTAssertTrue(app.buttons["Connect"].waitForExistence(timeout: 10))
        app.buttons["Connect"].click()
        let waiting = app.staticTexts["Open and unlock 2ndPass on another connected device."]
        XCTAssertTrue(waiting.waitForExistence(timeout: 5))
        XCTAssertFalse(app.progressIndicators.firstMatch.exists)
        app.buttons["Close"].click()
        XCTAssertFalse(waiting.exists)
    }
    func testAutoFillMappingControlsAndSettings() {
        let app = launch()
        edit(app)
        XCTAssertTrue(app.descendants(matching: .any)["autofill-mapping-Verification code"].firstMatch.waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertTrue(app.descendants(matching: .any)["autofill-mapping-Username"].firstMatch.exists, app.debugDescription)
        app.buttons["Cancel"].click()
        app.typeKey(",", modifierFlags: .command)
        app.buttons["AutoFill"].click()
        XCTAssertTrue(app.buttons["Open AutoFill Settings…"].waitForExistence(timeout: 5))
    }
    func testLockRequiresExplicitUnlock() {
        let app = launch()
        app.buttons["Lock"].click()
        let unlock = app.buttons["Unlock 2ndPass"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["All Items"].exists)
        XCTAssertFalse(app.buttons["Refresh"].exists)
        app.typeKey("r", modifierFlags: .command)
        XCTAssertTrue(unlock.exists)
        XCTAssertFalse(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Example Login,")).firstMatch.exists)
        unlock.click()
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Example Login,")).firstMatch.waitForExistence(timeout: 5))
    }
    func testEditorConcealsAcrossAppSwitchAndKeepsChanges() {
        let app = launch()
        edit(app); changeName(app)
        app.buttons["Reveal password input"].click()
        XCTAssertTrue(app.textFields["password value"].exists)
        let finder = XCUIApplication(bundleIdentifier: "com.apple.finder")
        finder.activate()
        app.activate()
        XCTAssertTrue(app.secureTextFields["password value"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.textFields["password value"].exists)
        XCTAssertEqual(app.textFields["Item name"].value as? String, "Changed Login")
    }
    func testNavigationSaveAndCancel() {
        let app = launch()
        edit(app); changeName(app)
        app.buttons["Recently Deleted"].click()
        XCTAssertTrue(app.sheets.buttons["Discard Changes"].waitForExistence(timeout: 5), app.windows.debugDescription)
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertEqual(app.textFields["Item name"].value as? String, "Changed Login")
        app.buttons["Recently Deleted"].click()
        app.sheets.buttons["Save Changes"].click()
        XCTAssertTrue(app.staticTexts["No recently deleted items"].waitForExistence(timeout: 5))
        app.buttons["All Items"].click()
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Changed Login,")).firstMatch.waitForExistence(timeout: 5))
    }
    func testCloseAndQuitPromptBeforeDiscarding() {
        let app = launch()
        edit(app); changeName(app)
        app.typeKey("w", modifierFlags: .command)
        XCTAssertTrue(app.sheets.buttons["Discard Changes"].waitForExistence(timeout: 5), app.windows.debugDescription)
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertEqual(app.textFields["Item name"].value as? String, "Changed Login")
        app.typeKey("q", modifierFlags: .command)
        XCTAssertTrue(app.sheets.buttons["Discard Changes"].waitForExistence(timeout: 5), app.windows.debugDescription)
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertEqual(app.textFields["Item name"].value as? String, "Changed Login")
        app.typeKey("q", modifierFlags: .command)
        app.sheets.buttons["Discard Changes"].click()
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 5))
    }
    func testNativeSearchPreservesDraftAndSettingsCategories() {
        let app = launch()
        edit(app); changeName(app)
        app.typeKey("f", modifierFlags: .command)
        let search = app.textFields["Item search"]
        XCTAssertTrue(search.waitForExistence(timeout: 5), app.debugDescription)
        search.typeText("no-match")
        XCTAssertTrue(app.staticTexts["No Search Results"].waitForExistence(timeout: 5))
        XCTAssertEqual(app.textFields["Item name"].value as? String, "Changed Login")
        XCTAssertFalse(app.sheets.buttons["Discard Changes"].exists)
        app.typeKey(",", modifierFlags: .command)
        XCTAssertTrue(app.buttons["Security"].waitForExistence(timeout: 5), app.debugDescription)
        app.buttons["Security"].click()
        XCTAssertTrue(app.popUpButtons["inactivity-timeout"].exists, app.debugDescription)
        app.buttons["AutoFill"].click()
        XCTAssertTrue(app.buttons["Open AutoFill Settings…"].waitForExistence(timeout: 5))
        let shot = XCTAttachment(screenshot: app.screenshot()); shot.name = "Categorized Settings"; shot.lifetime = .keepAlways; add(shot)
    }
    func testVaultDetailsAndRenameDiscardGuard() {
        let app = launch()
        XCTAssertFalse(app.buttons["Vault Details"].exists)
        app.buttons["personal"].firstMatch.rightClick()
        app.menuItems["Vault Details…"].click()
        XCTAssertTrue(app.buttons["Rename Vault…"].waitForExistence(timeout: 5))
        app.buttons["Rename Vault…"].click()
        let name = app.sheets.textFields["Name"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.click(); name.typeKey("a", modifierFlags: .command); name.typeText("renamed")
        app.sheets.buttons["Cancel"].click()
        XCTAssertTrue(app.sheets.buttons["Keep Editing"].waitForExistence(timeout: 5))
        app.sheets.buttons["Keep Editing"].click()
        XCTAssertEqual(name.value as? String, "renamed")
        app.sheets.buttons["Cancel"].click()
        app.sheets.buttons["Discard Changes"].click()
        XCTAssertTrue(app.buttons["Rename Vault…"].waitForExistence(timeout: 5))
        let shot = XCTAttachment(screenshot: app.screenshot()); shot.name = "Vault Details"; shot.lifetime = .keepAlways; add(shot)
    }

}
#endif
