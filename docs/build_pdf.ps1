$ErrorActionPreference = "Stop"

Write-Host "Building HTML documentation..."
python -m sphinx -b html . _build/html

Write-Host ""
Write-Host "✓ Documentation built successfully!"
Write-Host ""
Write-Host "HTML documentation: _build/html/index.html"
Write-Host ""
Write-Host "To save as PDF:"
Write-Host "  1. Open: _build/html/index.html in your web browser"
Write-Host "  2. Press Ctrl+P to print"
Write-Host "  3. Select 'Save as PDF' as the printer"


