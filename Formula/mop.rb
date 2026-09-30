class Mop < Formula
  desc "Manage encrypted secrets with your Mac's Secure Enclave"
  homepage "https://github.com/koehn/2ndPass"
  url "https://github.com/koehn/2ndPass/archive/38a1cccd7ea18794a04ac5cff6f571cc92a9d29f.tar.gz"
  version "0.3.0"
  sha256 "8be1d9c2ccc907df25a20c32410b8d721e3433f8a493182ab8cde096e5e009d3"
  license "MIT"

  depends_on xcode: ["16.0", :build]
  depends_on macos: :sequoia

  def install
    system "swift", "build", *std_swift_args, "--disable-sandbox", "--force-resolved-versions", "--product", "mop"
    bin.install ".build/release/mop"
    # Older stable releases lack the estimator; HEAD needs its SwiftPM resources.
    if File.directory?(".build/release/zxcvbn_zxcvbn.bundle")
      bin.install ".build/release/zxcvbn_zxcvbn.bundle"
      (share/"licenses/mop").install ".build/checkouts/zxcvbn-swift/LICENSE" => "zxcvbn-LICENSE.txt"
    end
    system "/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--timestamp=none", bin/"mop"
    system "/usr/bin/codesign", "--verify", "--strict", bin/"mop"
    man1.install "docs/man/mop.1"
    generate_completions_from_executable(bin/"mop", "completion")
  end

  test do
    ENV["MOP_VAULT_FILE"] = (testpath/"missing.mopfile").to_s
    ENV["MOP_STATE_DIRECTORY"] = (testpath/"state").to_s
    (testpath/"template").write "literal {{ other }}\n"
    assert_equal "literal {{ other }}\n", shell_output("#{bin}/mop inject --in-file #{testpath}/template")
    (testpath/"test.env").write "MOP_BREW_TEST=from-dotenv\n"
    assert_equal "from-dotenv", shell_output(
      "#{bin}/mop run --env-file #{testpath}/test.env -- /bin/sh -c 'printf %s \"$MOP_BREW_TEST\"'",
    )
    assert_match "Vault file not found", shell_output("#{bin}/mop read mop://test/item/field 2>&1", 9)
    assert_path_exists man1/"mop.1"
    assert_path_exists bash_completion/"mop"
    assert_path_exists zsh_completion/"_mop"
    assert_path_exists fish_completion/"mop.fish"
    system "/usr/bin/codesign", "--verify", "--strict", bin/"mop"
  end
end
