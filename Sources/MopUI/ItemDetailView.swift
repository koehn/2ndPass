import SwiftUI
import MopCore
import MopAppSupport

struct ItemDetailView: View {
    @Bindable var model: AppModel
    let itemName: String
    @Environment(\.dynamicTypeSize) private var textSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AppStorage("developerToolsEnabled") private var developerTools = false
    @FocusState private var focusedField: String?
    @State private var dropTarget: String?
    @State private var hoveredField: String?
    @FocusState private var focusedCopy: String?

    private var creating: Bool { model.itemDraft?.isNew == true }
    private var editingVaultName: String {
        creating ? (model.itemDraft.flatMap { model.catalogs[$0.vault]?.vault } ?? model.vaultName) : model.vaultName
    }
    private var editingItem: Bool { model.itemDraft?.mode == .item }
    private var fields: [ItemDraft.Field] {
        model.itemDraft?.fields ?? model.selectedTypedItem?.fields.map { ItemDraft.Field($0) } ?? []
    }
    private var motion: Animation? { reduceMotion ? nil : .easeInOut(duration: 0.18) }
    private func change(_ action: () -> Void) { withAnimation(motion, action) }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 8) { breadcrumb; Spacer(minLength: 16); editActions }
                VStack(alignment: .leading, spacing: 12) { breadcrumb; editActions }
            }
            .font(.callout)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Vault and item")
            Divider()
            if creating && model.allVaults {
                Picker("Vault", selection: Binding(get: { model.itemDraft?.vault ?? "" }, set: { model.chooseCreationVault($0) })) {
                    ForEach(model.itemCreationVaults) { vault in
                        Text(model.vaultLabel(vault)).tag(vault.id)
                    }
                }.frame(maxWidth: 320).disabled(model.busy)
            }
            if editingItem {
                TextField("Item name", text: Binding(get: { model.itemDraft?.name ?? itemName }, set: { model.itemDraft?.name = $0 }))
                    .font(.largeTitle.weight(.semibold)).textFieldStyle(.plain)
                    .focused($focusedField, equals: "item-name").accessibilityLabel("Item name")
                if !creating && model.itemDraft?.name != itemName {
                    Text("Renaming changes this item’s references.").font(.caption).foregroundStyle(.secondary)
                }
            } else { Text(itemName).font(.largeTitle).fontWeight(.semibold) }
            if editingItem {
                Picker("Item type", selection: Binding(get: { model.itemDraft?.type ?? .custom }, set: { model.changeDraftType($0) })) {
                    ForEach(ItemType.templateTypes, id: \.self) { Text($0.label).tag($0) }
                    if !creating && model.itemDraft?.type == .custom { Text("Custom").tag(ItemType.custom) }
                }.frame(maxWidth: 280).disabled(model.busy)
                Text("Drag the handles to reorder fields. Changes are saved together when you choose Save.")
                    .font(.caption).foregroundStyle(.secondary)
            } else { Text(model.selectedTypedItem?.type.label ?? "Custom").foregroundStyle(.secondary) }
            if let item = model.itemDraft?.item ?? model.selectedTypedItem, item.type == .login {
                if let reason = AutoFillEntry.exclusionReason(for: item) {
                    Label("AutoFill unavailable: " + reason, systemImage: "info.circle")
                        .font(.callout).foregroundStyle(.secondary)
                } else {
                    Label("Fields ready for AutoFill", systemImage: "checkmark.circle")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            ForEach(fields.filter { edits($0) || $0.type != .notes || $0.value != "" }) { field in
                fieldRow(field)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
            if editingItem {
                Button("Add field", systemImage: "plus") {
                    change { model.itemDraft?.fields.append(ItemDraft.Field(ItemField(path: "", value: ""), existing: false)) }
                    focusedField = fields.last?.id
                }.disabled(model.busy)
            }
            if model.itemDraft != nil {
                Text("Unsaved changes are discarded when you leave this item or lock Mop.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if model.offline {
                Label("Available offline. Changes require an iCloud connection.", systemImage: "icloud.slash")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }.padding(24).frame(maxWidth: 760, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { if creating { focusedField = "item-name" } }
        .task(id: model.copyFeedback?.id) {
            guard let feedback = model.copyFeedback else { return }
            do { try await Task.sleep(for: .seconds(2)) } catch { return }
            if model.copyFeedback?.id == feedback.id { model.copyFeedback = nil }
        }
        .onDisappear { model.copyFeedback = nil }
        .onChange(of: model.itemDraft?.id) { old, new in
            if old != nil && new == nil { focusedField = nil; dropTarget = nil }
        }
        .animation(model.isActive && model.authenticated ? motion : nil, value: model.itemDraft?.id)
        // Security transitions must never animate secret-bearing views out.
        .transaction { if !model.isActive || !model.authenticated { $0.disablesAnimations = true } }
    }

    private var breadcrumb: some View {
        HStack(spacing: 8) {
                Image(systemName: "lock.shield").foregroundStyle(.secondary)
                Text(editingVaultName).foregroundStyle(.secondary)
        }.lineLimit(1)
    }
    @ViewBuilder private var editActions: some View {
                if model.itemDraft == nil {
                    HStack(spacing: 12) {
                        Button("Edit item") { change { model.beginItemEditing() }; focusedField = "item-name" }
                            .disabled(model.busy || model.offline)
                        Menu {
                            Button("Delete item…", role: .destructive) {
                                if let item = model.selectedTypedItem {
                                    model.itemToDelete = ItemRow(id: .init(vault: model.vault, name: item.name), vaultName: model.vaultName, item: item)
                                }
                            }.disabled(model.busy || model.offline)
                        } label: { Image(systemName: "ellipsis.circle").accessibilityLabel("Item actions") }
                    }
                } else if editingItem { saveControls }
    }

    private var saveControls: some View {
        HStack {
            Button("Cancel") { change { model.cancelItemEditing() }; focusedField = nil }
                .keyboardShortcut(.cancelAction)
            Button("Save") { model.saveItemDraft() }
                .buttonStyle(.borderedProminent).keyboardShortcut("s", modifiers: .command)
                .disabled(model.itemDraft?.valid(vaultName: editingVaultName) != true)
        }.disabled(model.busy)
    }

    private func copyVisibility(_ field: ItemDraft.Field) -> Double {
        #if os(macOS)
        hoveredField == field.id || focusedCopy == field.id ? 1 : 0
        #else
        1
        #endif
    }
    private func isTemplate(_ field: ItemDraft.Field) -> Bool {
        field.isTemplate || (!creating && model.selectedTypedItem?.isTemplateField(field.field) == true)
    }
    private func edits(_ field: ItemDraft.Field) -> Bool {
        editingItem || model.itemDraft?.mode == .value(field.path)
    }
    private func reference(_ field: ItemDraft.Field) -> SecretReference? {
        try? SecretReference(vault: model.vaultName, relativePath: SecretReference.encode(itemName) + "/" + field.encodedPath)
    }
    private func binding<T>(_ field: ItemDraft.Field, _ key: WritableKeyPath<ItemDraft.Field, T>, fallback: T) -> Binding<T> {
        Binding(get: { model.itemDraft?.fields.first { $0.id == field.id }?[keyPath: key] ?? fallback }, set: { value in
            model.activity()
            guard let index = model.itemDraft?.fields.firstIndex(where: { $0.id == field.id }) else { return }
            model.itemDraft?.fields[index][keyPath: key] = value
        })
    }
    private func valueBinding(_ field: ItemDraft.Field) -> Binding<String> {
        Binding(get: { model.itemDraft?.fields.first { $0.id == field.id }?.value ?? "" }, set: { value in
            model.activity()
            guard let index = model.itemDraft?.fields.firstIndex(where: { $0.id == field.id }) else { return }
            model.itemDraft?.fields[index].value = value
        })
    }
    private var fieldLayout: AnyLayout {
        #if os(iOS)
        if textSize.isAccessibilitySize {
            return AnyLayout(VStackLayout(alignment: .leading, spacing: 12))
        }
        #endif
        return AnyLayout(HStackLayout(alignment: .center, spacing: 12))
    }
    private func fieldRow(_ field: ItemDraft.Field) -> some View {
        fieldLayout {
            if editingItem { handle(field) }
            VStack(alignment: .leading, spacing: 8) {
                if !field.existing && !field.isTemplate {
                    TextField("Field or section/field", text: binding(field, \.path, fallback: field.path))
                        .textFieldStyle(.roundedBorder).focused($focusedField, equals: field.id)
                    Picker("Field type", selection: binding(field, \.type, fallback: field.type)) {
                        ForEach(FieldType.allCases, id: \.self) { Text($0.label).tag($0) }
                    }.frame(maxWidth: 280)
                } else {
                    Text(field.path.split(separator: "/").map { String($0).removingPercentEncoding ?? String($0) }.joined(separator: " / ").capitalized)
                        .font(.caption).foregroundStyle(.secondary)
                }
                if edits(field) {
                    valueInput(field)
                    if let error = field.validationError {
                        Text(error).font(.caption).foregroundStyle(.red)
                            .accessibilityLabel("\(field.path): \(error)")
                    }
                    if field.value == nil {
                        Text("Stored value unchanged. Enter a replacement to change it.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if !editingItem { HStack { Spacer(); saveControls }.font(.callout) }
                } else if let ref = reference(field) {
                    fieldLayout {
                        displayedValue(field, ref: ref)
                        fieldActions(field, ref: ref)
                    }
                }
                if field.type == .password {
                    if edits(field) {
                        PasswordGeneratorButton(model: model) { password in
                            guard edits(field) else { return }
                            valueBinding(field).wrappedValue = password
                        }
                    }
                    PasswordStrengthView(password: edits(field) ? field.passwordToEstimate : nil,
                                         storedScore: field.storedPasswordQuality)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
            if editingItem && !isTemplate(field) {
                Button(role: .destructive) {
                    change { model.itemDraft?.fields.removeAll { $0.id == field.id } }
                } label: { Image(systemName: "minus.circle") }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .help("Remove field when saved").accessibilityLabel("Remove \(field.path)")

            }
        }
        .padding(16)
        .background(hoveredField == field.id ? Color.primary.opacity(0.045) : Color.primary.opacity(0.025), in: RoundedRectangle(cornerRadius: 10))
        .contentShape(RoundedRectangle(cornerRadius: 10))
        .onHover { hovering in
            if hovering { hoveredField = field.id }
            else if hoveredField == field.id { hoveredField = nil }
        }
        .animation(reduceMotion ? nil : .easeOut(duration: 0.12), value: hoveredField == field.id)
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(dropTarget == field.id && editingItem ? Color.accentColor : Color.clear, lineWidth: 2))
        .overlay {
            let showingFeedback = model.copyFeedback?.reference == reference(field) && model.copyFeedback != nil && !editingItem
            ZStack {
                if showingFeedback, let feedback = model.copyFeedback {
                    Label(feedback.message, systemImage: "checkmark.circle.fill")
                        .font(.callout.weight(.medium))
                        .padding(.horizontal, 14).padding(.vertical, 8)
                        .background(.regularMaterial, in: Capsule())
                        .shadow(color: .black.opacity(0.12), radius: 4, y: 2)
                        .accessibilityIdentifier("copy-feedback-" + field.path)
                        .transition(.opacity)
                }
            }
            .animation(reduceMotion ? nil : (showingFeedback ? .easeOut(duration: 0.12) : .easeInOut(duration: 0.4)), value: showingFeedback)
            .allowsHitTesting(false)
        }
        .disabled(model.busy)
        .dropDestination(for: String.self) { values, _ in
            guard editingItem, !model.busy, values.count == 1,
                  let source = model.itemDraft?.fields.first(where: { $0.dragID.uuidString == values[0] }) else { return false }
            change { model.itemDraft?.move(source.id, to: field.id) }
            dropTarget = nil
            return true
        } isTargeted: { targeted in
            if targeted && editingItem { dropTarget = field.id }
            else if dropTarget == field.id { dropTarget = nil }
        }
    }
    private func fieldActions(_ field: ItemDraft.Field, ref: SecretReference) -> some View {
        HStack(spacing: 4) {
            #if os(macOS)
            if field.type.concealed && field.type != .otp {
                Button {
                    if model.selected == ref && model.revealed != nil { model.conceal() }
                    else { model.selectField(ref); model.read(copy: false) }
                } label: {
                    Image(systemName: model.selected == ref && model.revealed != nil ? "eye.slash" : "eye").mopControlTarget()
                }
                .buttonStyle(.borderless)
                .accessibilityLabel((model.selected == ref && model.revealed != nil ? "Conceal " : "Reveal ") + field.path)
            }
            Button { model.selectField(ref); model.read(copy: true) } label: {
                Label("Copy", systemImage: "doc.on.doc").mopControlTarget()
            }
            .buttonStyle(.borderless).labelStyle(.iconOnly).foregroundStyle(Color.accentColor)
            .focused($focusedCopy, equals: field.id)
            .opacity(copyVisibility(field))
            .help("Copy value").accessibilityLabel("Copy \(field.path) value")
            #endif
            fieldMenu(field, ref: ref)
        }
        .frame(maxWidth: textSize.isAccessibilitySize ? .infinity : nil, alignment: .trailing)
        .disabled(model.itemDraft != nil)
    }

    private func handle(_ field: ItemDraft.Field) -> some View {
        Image(systemName: "line.3.horizontal")
            .foregroundStyle(.secondary).padding(.vertical, 8).padding(.horizontal, 4)
            .contentShape(Rectangle())
            // Only an opaque row token enters the pasteboard, never field data.
            .draggable(field.dragID.uuidString) { Image(systemName: "line.3.horizontal").padding(8) }
            .help("Drag to reorder. Control-click for move commands.")
            .accessibilityLabel("Reorder \(field.path)")
            .accessibilityAddTraits(.isButton)
            .accessibilityAction(named: Text("Move up")) { move(field, offset: -1) }
            .accessibilityAction(named: Text("Move down")) { move(field, offset: 1) }
            .contextMenu {
                Button("Move up") { move(field, offset: -1) }.disabled(fields.first?.id == field.id)
                Button("Move down") { move(field, offset: 1) }.disabled(fields.last?.id == field.id)
            }
    }
    private func move(_ field: ItemDraft.Field, offset: Int) {
        guard !model.busy, let index = fields.firstIndex(where: { $0.id == field.id }), fields.indices.contains(index + offset) else { return }
        change { model.itemDraft?.move(field.id, to: fields[index + offset].id) }
    }
    @ViewBuilder private func valueInput(_ field: ItemDraft.Field) -> some View {
        let placeholder = field.value == nil ? "Unchanged — enter replacement" : "Value (empty allowed)"
        Group {
            if field.type == .password {
                TextField(placeholder, text: valueBinding(field))
            } else if field.type.concealed {
                SecureField(field.type == .otp ? "OTP seed or otpauth URL" : placeholder, text: valueBinding(field))
            } else if field.type == .notes {
                TextEditor(text: valueBinding(field)).frame(minHeight: 100).accessibilityLabel("\(field.path) value")
            } else { TextField(placeholder, text: valueBinding(field)) }
        }
        .textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced))
        .focused($focusedField, equals: field.existing ? field.id : field.id + ":value")
        .accessibilityLabel("\(field.path) value")
    }
    private func displayedValue(_ field: ItemDraft.Field, ref: SecretReference) -> some View {
        Group {
            if field.type == .otp {
                OTPCodeView(model: model, reference: ref)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Text((model.selected == ref ? model.revealed : nil).map { String(decoding: $0, as: UTF8.self) } ?? field.value ?? "••••••••")
                    .font(.system(.body, design: field.type.concealed ? .monospaced : .default)).textSelection(.disabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { model.selectField(ref); model.read(copy: true) }
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Copy value")
        .accessibilityAction { model.selectField(ref); model.read(copy: true) }
        .help("Copy value")
        .disabled(model.itemDraft != nil || !model.isActive || !model.authenticated)
    }
    private func fieldMenu(_ field: ItemDraft.Field, ref: SecretReference) -> some View {
        Menu {
            Button("Edit value", systemImage: "pencil") {
                model.selectField(ref)
                change { model.beginItemEditing(replacing: field.path) }
                focusedField = field.id
            }.disabled(model.offline)
            if field.type != .otp && model.selected == ref && model.revealed != nil {
                Button("Conceal", systemImage: "eye.slash") { model.conceal() }
            } else if field.type != .otp && field.value == nil {
                Button("Reveal", systemImage: "eye") { model.selectField(ref); model.read(copy: false) }
            }
            Button("Copy value", systemImage: "doc.on.doc") { model.selectField(ref); model.read(copy: true) }
            if field.type == .website, let value = field.value,
               let url = URL(string: value), ["https", "http"].contains(url.scheme?.lowercased() ?? ""), url.host != nil {
                Link("Open website", destination: url)
            }
            if developerTools {
                Button("Copy reference", systemImage: "link") { model.selectField(ref); model.copyReference() }
            }
            if !isTemplate(field) {
                Divider()
                Button("Delete field…", systemImage: "trash", role: .destructive) {
                    model.selectField(ref); model.deleteConfirmation = true
                }.disabled(model.offline)
            }
        } label: {
            #if os(iOS)
            Image(systemName: "chevron.down").font(.caption.weight(.semibold))
                .frame(width: 44, height: 44, alignment: .trailing).contentShape(Rectangle())
            #else
            Image(systemName: "chevron.down").font(.caption.weight(.semibold)).frame(width: 24, height: 24)
            #endif
        }
        .mopMenuStyle()
        .help("Field actions").accessibilityLabel("Actions for \(field.path)")
    }
}

private struct OTPCodeView: View {
    let model: AppModel
    let reference: SecretReference
    @State private var code: String?
    @State private var invalid = false
    @State private var expires: Date?
    @State private var period = 30
    private var active: Bool { model.isActive && model.authenticated }
    private var identity: String { "\(reference.description)|\(model.vault)|\(model.catalog?.revision ?? "")|\(active)" }
    var body: some View {
        HStack(spacing: 12) {
            Text(active ? (invalid ? "Invalid OTP — replace the secret" : code ?? "••••••") : "••••••")
                .accessibilityIdentifier("otp-code-" + reference.description)
            if active, code != nil, let expires {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let remaining = max(0, Int(ceil(expires.timeIntervalSince(context.date))))
                    let tint: Color = remaining <= 5 ? .red : .green
                    HStack(spacing: 3) {
                        ZStack {
                            Circle().stroke(tint.opacity(0.2), lineWidth: 3)
                            Circle().trim(from: 0, to: min(1, Double(remaining) / Double(period)))
                                .stroke(tint, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                                .rotationEffect(.degrees(-90))
                        }.frame(width: 16, height: 16)
                        Text("\(remaining)").monospacedDigit().frame(minWidth: 16, alignment: .leading)
                    }
                    .font(.caption).foregroundStyle(tint)
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("Code expires in \(remaining) seconds")
                    .accessibilityIdentifier("otp-countdown-" + reference.description)
                }
            }
        }
            .font(.system(.body, design: .monospaced)).monospacedDigit()
            .foregroundStyle(invalid ? Color.red : Color.primary)
            .textSelection(.disabled)
            .task(id: identity) {
                code = nil; expires = nil; invalid = false
                guard active else { return }
                while !Task.isCancelled {
                    do {
                        let next = try await model.currentOTP(reference)
                        guard !Task.isCancelled else { return }
                        code = next.code; expires = next.expires; period = next.period; invalid = false
                    } catch {
                        guard !Task.isCancelled else { return }
                        code = nil; expires = nil; invalid = error as? MopError == .invalidOTP
                        return
                    }
                    do { try await Task.sleep(for: .seconds(1)) } catch { return }
                }
            }
            .onDisappear { code = nil; expires = nil }
    }
}
