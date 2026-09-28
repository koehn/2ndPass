import SwiftUI

/// The same tag receives the same semantic system color across launches and devices.
struct TagBadges: View {
    let tags: [String]
    @Environment(\.colorSchemeContrast) private var contrast
    private static let palette: [Color] = [.blue, .teal, .green, .indigo, .purple, .pink, .orange, .brown]

    private func color(for tag: String) -> Color {
        let normalized = tag.trimmingCharacters(in: .whitespacesAndNewlines)
            .precomposedStringWithCanonicalMapping.lowercased()
        // Swift's Hasher is randomized each launch; use a stable hash for colors.
        let hash = normalized.utf8.reduce(UInt64(14695981039346656037)) {
            ($0 ^ UInt64($1)) &* 1099511628211
        }
        return Self.palette[Int(hash % UInt64(Self.palette.count))]
    }

    var body: some View {
        TagFlowLayout {
            ForEach(Array(tags.enumerated()), id: \.offset) { _, tag in
                let tint = color(for: tag)
                HStack(spacing: 4) {
                    Image(systemName: "tag.fill").foregroundStyle(tint)
                    Text(tag).foregroundStyle(.primary).textSelection(.enabled)
                }
                .font(.caption.weight(.medium))
                .padding(.horizontal, 9).padding(.vertical, 5)
                .background(tint.opacity(contrast == .increased ? 0.25 : 0.13), in: Capsule())
                .overlay(Capsule().strokeBorder(tint.opacity(contrast == .increased ? 0.8 : 0.35)))
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Tag: " + tag)
            }
        }
    }
}

/// Wrap badges instead of truncating them or making the item view scroll sideways.
private struct TagFlowLayout: Layout {
    private let spacing: CGFloat = 6

    private func arrange(_ subviews: Subviews, width: CGFloat) -> (size: CGSize, frames: [CGRect]) {
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        var usedWidth: CGFloat = 0
        var frames: [CGRect] = []
        for subview in subviews {
            let size = subview.sizeThatFits(ProposedViewSize(width: width.isFinite ? width : nil, height: nil))
            if x > 0 && x + size.width > width {
                x = 0; y += rowHeight + spacing; rowHeight = 0
            }
            frames.append(CGRect(origin: CGPoint(x: x, y: y), size: size))
            usedWidth = max(usedWidth, x + size.width)
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return (CGSize(width: usedWidth, height: y + rowHeight), frames)
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(subviews, width: max(0, proposal.width ?? .infinity)).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let layout = arrange(subviews, width: bounds.width)
        for (subview, frame) in zip(subviews, layout.frames) {
            subview.place(at: CGPoint(x: bounds.minX + frame.minX, y: bounds.minY + frame.minY),
                          proposal: ProposedViewSize(frame.size))
        }
    }
}
