import Foundation
import MopCore

enum ItemCollection: Equatable, Codable {
    case all, vault(String), favorites, archive, recentlyDeleted
    case recentlyAdded, recentlyChanged, recentlyUsed

    var sidebarID: String {
        switch self {
        case .all: "all"
        case .vault(let id): "vault:" + id
        case .favorites: "favorites"
        case .archive: "archive"
        case .recentlyDeleted: "deleted"
        case .recentlyAdded: "recent-added"
        case .recentlyChanged: "recent-changed"
        case .recentlyUsed: "recent-used"
        }
    }
    var isRecent: Bool {
        switch self { case .recentlyAdded, .recentlyChanged, .recentlyUsed: true; default: false }
    }
    var title: String? {
        switch self {
        case .all: "All Items"
        case .vault: nil
        case .favorites: "Favorites"
        case .archive: "Archive"
        case .recentlyDeleted: "Recently Deleted"
        case .recentlyAdded: "Recently Added"
        case .recentlyChanged: "Recently Changed"
        case .recentlyUsed: "Recently Used"
        }
    }
}
