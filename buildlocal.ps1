# Copy the dist folder and the package.json file to ./../facturador-backend/open-factura path
# Usage: ./copifiles.ps1

$distSource = "dist"
$packageSource = "package.json"
$packageLockSource = "package-lock.json"
$destination = "./../facturador-backend/open-factura"

Write-Host "Building package with npm run build"
bun run build

if (Test-Path $destination) {
    Write-Host "Removing open-factura folder in ./../facturador-backend path"
    Remove-Item -Path "./../facturador-backend/open-factura" -Recurse -Force
}

Write-Host "Copying files to ./../facturador-backend/open-factura path"

Copy-Item -Path $distSource -Destination ($destination + "/dist") -Recurse -Force
Copy-Item -Path $packageSource -Destination $destination -Force
Copy-Item -Path $packageLockSource -Destination $destination -Force

Write-Host "Files copied successfully"