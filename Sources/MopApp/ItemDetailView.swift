import SwiftUI
import MopCore

struct ItemDetailView: View {
    @Bindable var model: AppModel
    let itemName: String
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
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
            HStack(spacing: 8) {
                Image(systemName: "lock.shield").foregroundStyle(.secondary)
                Text(editingVaultName).foregroundStyle(.secondary)
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                Text(creating ? "New item" : itemName).lineLimit(1)
                Spacer(minLength: 16)
                if model.itemDraft == nil {
                    Button("Edit item") { change { model.beginItemEditing() }; focusedField = "item-name" }
                        .disabled(model.busy || model.offline)
                } else if editingItem { saveControls }
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
                    ForEach(ItemType.allCases, id: \.self) { Text($0.label).tag($0) }
                }.frame(maxWidth: 280).disabled(model.busy)
                Text("Drag the handles to reorder fields. Changes are saved together when you choose Save.")
                    .font(.caption).foregroundStyle(.secondary)
            } else { Text(model.selectedTypedItem?.type.label ?? "Custom").foregroundStyle(.secondary) }
            ForEach(fields) { field in
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
                Label("Read-only snapshot. Remote revocation cannot be checked.", systemImage: "icloud.slash")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }.padding(28).frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { if creating { focusedField = "item-name" } }
        .onChange(of: model.itemDraft?.id) { old, new in
            if old != nil && new == nil { focusedField = nil; dropTarget = nil }
        }
        .animation(model.isActive && model.authenticated ? motion : nil, value: model.itemDraft?.id)
        // Security transitions must never animate secret-bearing views out.
        .transaction { if !model.isActive || !model.authenticated { $0.disablesAnimations = true } }
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
            guard let index = model.itemDraft?.fields.firstIndex(where: { $0.id == field.id }) else { return }
            model.itemDraft?.fields[index][keyPath: key] = value
        })
    }
    private func valueBinding(_ field: ItemDraft.Field) -> Binding<String> {
        Binding(get: { model.itemDraft?.fields.first { $0.id == field.id }?.value ?? "" }, set: { value in
            guard let index = model.itemDraft?.fields.firstIndex(where: { $0.id == field.id }) else { return }
            model.itemDraft?.fields[index].value = value
        })
    }
    private func fieldRow(_ field: ItemDraft.Field) -> some View {
        HStack(alignment: .top, spacing: 12) {
            if editingItem { handle(field) }
            VStack(alignment: .leading, spacing: 8) {
                if !field.existing && !field.isTemplate {
                    TextField("Field or section/field", text: binding(field, \.path, fallback: field.path))
                        .textFieldStyle(.roundedBorder).focused($focusedField, equals: field.id)
                    Picker("Field type", selection: binding(field, \.type, fallback: field.type)) {
                        ForEach(FieldType.allCases, id: \.self) { Text($0.label).tag($0) }
                    }.frame(maxWidth: 280)
                } else {
                    Text(field.path.split(separator: "/").map { String($0).removingPercentEncoding ?? String($0) }.joined(separator: " / "))
                        .font(.caption).foregroundStyle(.secondary)
                }
                if edits(field) {
                    valueInput(field)
                    if field.value == nil {
                        Text("Stored value unchanged. Enter a replacement to change it.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if !editingItem { HStack { Spacer(); saveControls }.font(.callout) }
                } else if let ref = reference(field) { displayedValue(field, ref: ref) }
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
            } else if let ref = reference(field), !edits(field) {
                HStack(spacing: 8) {
                    Button { model.selectField(ref); model.read(copy: true) } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.borderless).foregroundStyle(Color.accentColor)
                    .focused($focusedCopy, equals: field.id)
                    .opacity(hoveredField == field.id || focusedCopy == field.id ? 1 : 0)
                    .help("Copy value").accessibilityLabel("Copy \(field.path) value")
                    fieldMenu(field, ref: ref)
                }.disabled(model.itemDraft != nil).padding(.top, 10)
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
        Text((model.selected == ref ? model.revealed : nil).map { String(decoding: $0, as: UTF8.self) } ?? field.value ?? "••••••••••••••••••••")
            .font(.system(.body, design: .monospaced)).textSelection(.disabled)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
    private func fieldMenu(_ field: ItemDraft.Field, ref: SecretReference) -> some View {
        Menu {
            Button("Edit value", systemImage: "pencil") {
                model.selectField(ref)
                change { model.beginItemEditing(replacing: field.path) }
                focusedField = field.id
            }.disabled(model.offline)
            if model.selected == ref && model.revealed != nil {
                Button("Conceal", systemImage: "eye.slash") { model.conceal() }
            } else if field.value == nil {
                Button("Reveal", systemImage: "eye") { model.selectField(ref); model.read(copy: false) }
            }
            Button("Copy value", systemImage: "doc.on.doc") { model.selectField(ref); model.read(copy: true) }
            Button("Copy reference", systemImage: "link") { model.selectField(ref); model.copyReference() }
            if !isTemplate(field) {
                Divider()
                Button("Delete field…", systemImage: "trash", role: .destructive) {
                    model.selectField(ref); model.deleteConfirmation = true
                }.disabled(model.offline)
            }
        } label: {
            Image(systemName: "chevron.down").font(.caption.weight(.semibold)).frame(width: 24, height: 24)
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        .help("Field actions").accessibilityLabel("Actions for \(field.path)")
    }
}
