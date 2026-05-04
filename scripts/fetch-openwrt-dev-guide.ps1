param(
    [string]$OutputDir = "tmp/openwrt-dev-guide"
)

$ErrorActionPreference = "Stop"

$pages = @(
    @{ Name = "developer-guide-start"; Path = "docs/guide-developer/start" },
    @{ Name = "overview"; Path = "docs/guide-developer/overview" },
    @{ Name = "packages"; Path = "docs/guide-developer/packages" },
    @{ Name = "package-policies"; Path = "docs/guide-developer/package-policies" },
    @{ Name = "dependencies"; Path = "docs/guide-developer/dependencies" },
    @{ Name = "feeds"; Path = "docs/guide-developer/feeds" },
    @{ Name = "using-sdk"; Path = "docs/guide-developer/obtain.firmware.sdk" },
    @{ Name = "single-package"; Path = "docs/guide-developer/toolchain/single.package" },
    @{ Name = "crosscompile"; Path = "docs/guide-developer/toolchain/crosscompile" },
    @{ Name = "procd-init-scripts"; Path = "docs/guide-developer/procd-init-scripts" },
    @{ Name = "procd-init-script-example"; Path = "docs/guide-developer/procd-init-script-example" },
    @{ Name = "uci"; Path = "docs/techref/uci" },
    @{ Name = "write-shell-script"; Path = "docs/guide-developer/write-shell-script" },
    @{ Name = "working-with-github-pr"; Path = "docs/guide-developer/working-with-github-pr" },
    @{ Name = "submitting-patches"; Path = "submitting-patches" }
)

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$manifest = @()

foreach ($page in $pages) {
    $url = "https://openwrt.org/$($page.Path)?do=export_raw"
    $target = Join-Path $OutputDir "$($page.Name).txt"

    Write-Host "Fetching $url"
    & curl.exe -fL --retry 3 --retry-delay 2 -o $target $url

    if ($LASTEXITCODE -ne 0) {
        throw "curl failed for $url with exit code $LASTEXITCODE"
    }

    $manifest += [pscustomobject]@{
        name = $page.Name
        path = $page.Path
        url = $url
        file = $target
    }
}

$manifestPath = Join-Path $OutputDir "manifest.json"
$manifest | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 $manifestPath

Write-Host "Wrote OpenWrt guide context to $OutputDir"
