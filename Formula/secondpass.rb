class Secondpass < Formula
  desc "Manage encrypted secrets with your Mac's Secure Enclave"
  homepage "https://2ndpass.app"
  license "MIT"
  head "https://github.com/koehn/mop.git", branch: "main"

  depends_on xcode: ["16.0", :build]
  depends_on macos: :sequoia

  def install
    system "swift", "build", *std_swift_args, "--disable-sandbox", "--force-resolved-versions", "--product", "2ndpass"
    bin.install ".build/release/2ndpass"
    # Older stable releases lack the estimator; HEAD needs its SwiftPM resources.
    if File.directory?(".build/release/zxcvbn_zxcvbn.bundle")
      bin.install ".build/release/zxcvbn_zxcvbn.bundle"
      (share/"licenses/2ndpass").install ".build/checkouts/zxcvbn-swift/LICENSE" => "zxcvbn-LICENSE.txt"
    end
    system "/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--timestamp=none", bin/"2ndpass"
    system "/usr/bin/codesign", "--verify", "--strict", bin/"2ndpass"
    man1.install "docs/man/2ndpass.1"
    generate_completions_from_executable(bin/"2ndpass", "completion")
  end

  test do
    ENV["MOP_STATE_DIRECTORY"] = (testpath/"state").to_s
    (testpath/"template").write "literal {{ other }}\n"
    assert_equal "literal {{ other }}\n", shell_output("#{bin}/2ndpass inject --in-file #{testpath}/template")
    (testpath/"test.env").write "MOP_BREW_TEST=from-dotenv\n"
    assert_equal "from-dotenv", shell_output(
      "#{bin}/2ndpass run --env-file #{testpath}/test.env -- /bin/sh -c 'printf %s \"$MOP_BREW_TEST\"'",
    )
    assert_match "2ndpass", shell_output("#{bin}/2ndpass --help")
    assert_path_exists man1/"2ndpass.1"
    assert_path_exists bash_completion/"2ndpass"
    assert_path_exists zsh_completion/"_2ndpass"
    assert_path_exists fish_completion/"2ndpass.fish"
    system "/usr/bin/codesign", "--verify", "--strict", bin/"2ndpass"
  end
end
