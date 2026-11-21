# SSH Relay Pro 5.7 Linux Desktop

Ubuntu 24.04 x64. Install the DEB once with the system package installer, or:

    sudo apt install ./ssh-relay-pro-5.7_5.7.0-1_amd64.deb

Then open SSH Relay Pro 5.7 from the desktop shortcut or applications menu as an ordinary user. Electron and production dependencies are bundled. Installation configures Chromium sandbox permissions and creates a trusted shortcut for logged-in desktop users. No automatic startup service is installed. Chromium sandboxing remains enabled.

Verified on Ubuntu 24.04.4 x64: clean previous application/profile/helper, one apt installation, then ordinary desktop launches. No post-install manual repairs or additional dependency installation were required. This validates installation and startup, not all remote-connection features.

See SHA256SUMS. Third-party licenses are included in the package. This is the one-time installation edition; it is not an extraction-only portable package.
