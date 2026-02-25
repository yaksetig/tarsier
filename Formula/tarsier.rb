class Tarsier < Formula
  desc "Formal verification tool for distributed consensus protocols"
  homepage "https://github.com/yaksetig/tarsier"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yaksetig/tarsier/releases/download/v#{version}/tarsier-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_AARCH64_DARWIN"
    else
      url "https://github.com/yaksetig/tarsier/releases/download/v#{version}/tarsier-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_X86_64_DARWIN"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yaksetig/tarsier/releases/download/v#{version}/tarsier-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA256_AARCH64_LINUX"
    else
      url "https://github.com/yaksetig/tarsier/releases/download/v#{version}/tarsier-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA256_X86_64_LINUX"
    end
  end

  def install
    bin.install "tarsier"
    bin.install "tarsier-certcheck" if File.exist? "tarsier-certcheck"
  end

  test do
    system "#{bin}/tarsier", "--help"
  end
end
