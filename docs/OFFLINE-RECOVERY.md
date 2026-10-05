# Recovery and device loss

Account-wide offline recovery of a live cloud vault is not currently available. If an enrolled device remains accessible, keep it unlocked while another device connects automatically through the same Apple Account.

For independent restoration, export a portable archive and retain its separate generated key. Restore creates a new owned vault without requiring original device keys or the original cloud zone. See [backup and restore](BACKUPS.md) for commands, limits and verification.

Device-local Secure Enclave credential keys cannot be backed up or restored. Register an independent credential or service recovery method on another device. Account recovery and resumable key rotation remain [roadmap](ROADMAP.md) work.
