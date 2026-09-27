import SwiftUI
import MopCore

/// Edits string components without discarding unfamiliar nested source data.
struct CompoundFieldEditor: View {
    let type: FieldType
    @Binding var value: String
    private var contents: CompoundField? { try? CompoundField(value.isEmpty ? "{}" : value) }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let contents {
                let standard = CompoundField.components(for: type)
                let known = Set(standard.map(\.key))
                let components = standard + contents.keys.filter { !known.contains($0) }.map { (key: $0, label: $0) }
                ForEach(components, id: \.key) { component in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(component.label).font(.caption).foregroundStyle(.secondary)
                        if contents.contains(component.key), contents.text(for: component.key) == nil {
                            Text(contents.valueDescription(for: component.key)).font(.system(.caption, design: .monospaced))
                            Text("Imported structured data is preserved when you edit other components.").font(.caption).foregroundStyle(.secondary)
                        } else {
                            TextField(component.label, text: Binding(get: {
                                self.contents?.text(for: component.key) ?? ""
                            }, set: { text in
                                if let updated = try? (self.contents ?? contents).replacing(component.key, with: text) {
                                    value = updated.encodedValue
                                }
                            })).textFieldStyle(.roundedBorder)
                        }
                    }
                }
            } else {
                Text("The value is not a valid structured field.").foregroundStyle(.red)
                Button("Replace with empty details") { value = "{}" }
            }
        }.privacySensitive()
    }
}
