param(
	[string]$Configuration = "Release",
	[string]$PublishDir = "publish\\Kiln"
)

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not [IO.Path]::IsPathRooted($PublishDir)) {
	$PublishDir = Join-Path $root $PublishDir
}
$PublishDir = [IO.Path]::GetFullPath($PublishDir)

dotnet publish (Join-Path $root "Kiln.Mcp\\Kiln.Mcp.csproj") -c $Configuration -o $PublishDir
if ($LASTEXITCODE -ne 0) {
	exit $LASTEXITCODE
}

$pluginsDir = Join-Path $PublishDir "Plugins"
New-Item -ItemType Directory -Force -Path $pluginsDir | Out-Null
Get-ChildItem -Path $PublishDir -Filter "Kiln.Plugins.*.dll" -File | ForEach-Object {
	Move-Item -Force -Path $_.FullName -Destination (Join-Path $pluginsDir $_.Name)
}
Get-ChildItem -Path $PublishDir -Filter "Kiln.Plugins.*.pdb" -File | ForEach-Object {
	Move-Item -Force -Path $_.FullName -Destination (Join-Path $pluginsDir $_.Name)
}

New-Item -ItemType Directory -Force -Path (Join-Path $PublishDir "ida") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $PublishDir "workspace") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $PublishDir "Tools\\Il2CppDumper") | Out-Null

$template = Join-Path $root "kiln.config.template.json"
if (Test-Path $template) {
	Copy-Item -Path $template -Destination (Join-Path $PublishDir "kiln.config.template.json") -Force
	$config = Join-Path $PublishDir "kiln.config.json"
	if (-not (Test-Path $config)) {
		Copy-Item -Path $template -Destination $config -Force
	}
}
