# flowguarder - Homebrew Formula
#
# This formula is intended for the flowguarder/homebrew-tap repository,
# NOT for maintenance in this project. The URL and SHA256 are templated
# by goreleaser during the release pipeline (Task 33).
#
# Install after adding the tap:
#   brew tap flowguarder/tap
#   brew install flowguarder
#
# Template variables replaced by goreleaser:
#   GORELEASER_CURRENT_TAG  -> version
#   GORELEASER_PREVIOUS_TAG -> used for bottle (optional)

class Flowguarder < Formula
  desc "Network flow analysis CLI that emits annotated Kubernetes NetworkPolicy manifests"
  homepage "https://github.com/flowguarder/flowguarder"
  url "https://github.com/flowguarder/flowguarder/releases/download/__VERSION__/flowguarder___VERSION___src.tar.gz"
  version "__VERSION__"
  sha256 "0" * 64

  license "MIT"

  depends_on "go" => :build

  head do
    url "https://github.com/flowguarder/flowguarder.git"
  end

  def install
    system "go", "build", "-ldflags", "-s -w", "-o", bin / "flowguarder", "./cmd/flowguarder"
  end

  test do
    assert_match "flowguarder", shell_output("#{bin}/flowguarder --version")
  end
end
