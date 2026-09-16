import Darwin

/// POSIX mode bits do not describe access granted by a macOS extended ACL.
public enum PrivateACL {
    public static func clear(_ fd: Int32) throws {
        guard let acl = acl_init(0) else { throw MopError.inputOutput }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_set_fd(fd, acl) == 0 else { throw MopError.inputOutput }
    }

    public static func validate(_ fd: Int32) throws {
        guard let acl = acl_get_fd(fd) else {
            // On Darwin, an open inode with no extended ACL returns ENOENT.
            guard errno == ENOENT else { throw MopError.filePermissions }
            return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_valid(acl) == 0 else { throw MopError.filePermissions }
        var entry: acl_entry_t?
        var selector = ACL_FIRST_ENTRY
        while true {
            let result = acl_get_entry(acl, Int32(selector.rawValue), &entry)
            // Darwin returns -1 at the end of the entry list.
            if result != 0 {
                guard errno == EINVAL else { throw MopError.filePermissions }
                break
            }
            guard let entry else { throw MopError.filePermissions }
            var tag = acl_tag_t(0)
            guard acl_get_tag_type(entry, &tag) == 0 else { throw MopError.filePermissions }
            guard tag != ACL_EXTENDED_ALLOW else { throw MopError.filePermissions }
            selector = ACL_NEXT_ENTRY
        }
    }
}
