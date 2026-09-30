class Secondpass < Formula
  desc "Manage encrypted secrets with your Mac's Secure Enclave"
  homepage "https://2ndpass.app"
  license "MIT"
  head "https://github.com/koehn/mop.git", branch: "main"

  depends_on xcode: ["16.0", :build]
  depends_on macos: :sequoia

  def install
    system "swift", "build", *std_swift_args, "--disable-sandbox", "--force-resolved-versions", "--product", "sp"
    bin.install ".build/release/sp"
    # Older stable releases lack the estimator; HEAD needs its SwiftPM resources.
    if File.directory?(".build/release/zxcvbn_zxcvbn.bundle")
      bin.install ".build/release/zxcvbn_zxcvbn.bundle"
      (share/"licenses/sp").install ".build/checkouts/zxcvbn-swift/LICENSE" => "zxcvbn-LICENSE.txt"
    end
    system "/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--timestamp=none", bin/"sp"
    system "/usr/bin/codesign", "--verify", "--strict", bin/"sp"
    man1.install "docs/man/sp.1"
    generate_completions_from_executable(bin/"sp", "completion")
  end

  test do
    ENV["MOP_STATE_DIRECTORY"] = (testpath/"state").to_s
    (testpath/"template").write "literal {{ other }}\n"
    assert_equal "literal {{ other }}\n", shell_output("#{bin}/sp inject --in-file #{testpath}/template")
    (testpath/"test.env").write "MOP_BREW_TEST=from-dotenv\n"
    assert_equal "from-dotenv", shell_output(
      "#{bin}/sp run --env-file #{testpath}/test.env -- /bin/sh -c 'printf %s \"$MOP_BREW_TEST\"'",
    )
    assert_match "sp", shell_output("#{bin}/sp --help")
    assert_path_exists man1/"sp.1"
    assert_path_exists bash_completion/"sp"
    assert_path_exists zsh_completion/"_sp"
    assert_path_exists fish_completion/"sp.fish"
    system "/usr/bin/codesign", "--verify", "--strict", bin/"sp"
  end
end
