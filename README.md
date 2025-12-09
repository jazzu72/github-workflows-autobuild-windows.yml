# github-workflows-autobuild-windows.yml
workflow_dispatch with runner input (pick windows-latest or your self-hosted label such as self-hosted, windows-self-hosted, or a custom label).  Safe PowerShell execution (-NoProfile -ExecutionPolicy Bypass).  Artifact upload (build output directory configurable).  Logs and exit-code handling so CI fails on errors.
