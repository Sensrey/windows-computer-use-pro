param(
    [Parameter(Mandatory=$true)][string]$ImagePath,
    [string]$Lang = "zh-Hans-CN"
)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    })[0]

    function Await-WinRT($WinRtTask, $ResultType, [int]$TimeoutMs = 4500) {
        $netTask = $asTaskGeneric.MakeGenericMethod($ResultType).Invoke($null, @($WinRtTask))
        if (-not $netTask.Wait($TimeoutMs)) {
            throw "OCR_ASYNC_TIMEOUT"
        }
        return $netTask.GetAwaiter().GetResult()
    }

    $null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
    $null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    $null = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    $null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
    $null = [Windows.Globalization.Language, Windows.Foundation, ContentType = WindowsRuntime]

    $file = Await-WinRT ([Windows.Storage.StorageFile]::GetFileFromPathAsync($ImagePath)) ([Windows.Storage.StorageFile])
    $stream = Await-WinRT ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    $bitmap = $null
    try {
        $decoder = Await-WinRT ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
        $bitmap = Await-WinRT ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        $pxW = [int]$bitmap.PixelWidth
        $pxH = [int]$bitmap.PixelHeight

        $language = New-Object Windows.Globalization.Language($Lang)
        $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($language)
        if ($null -eq $engine) {
            $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
        }
        if ($null -eq $engine) {
            @{ status = "no_ocr_engine"; actual_language = ""; pixel_size = @($pxW, $pxH); lines = @() } | ConvertTo-Json -Compress -Depth 6
            exit 0
        }
        $actualLang = [string]$engine.RecognizerLanguage.LanguageTag
        $ocrResult = Await-WinRT ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])

        $linesOut = @()
        foreach ($line in $ocrResult.Lines) {
            $rawWords = @($line.Words)
            if ($rawWords.Count -eq 0) { continue }
            $minX = [double]::MaxValue
            $minY = [double]::MaxValue
            $maxX = [double]::MinValue
            $maxY = [double]::MinValue
            $wordsOut = @()
            foreach ($w in $rawWords) {
                $r = $w.BoundingRect
                $wx1 = [int][Math]::Round($r.X)
                $wy1 = [int][Math]::Round($r.Y)
                $wx2 = [int][Math]::Round($r.X + $r.Width)
                $wy2 = [int][Math]::Round($r.Y + $r.Height)
                if ($r.X -lt $minX) { $minX = $r.X }
                if ($r.Y -lt $minY) { $minY = $r.Y }
                if (($r.X + $r.Width) -gt $maxX) { $maxX = $r.X + $r.Width }
                if (($r.Y + $r.Height) -gt $maxY) { $maxY = $r.Y + $r.Height }
                $wordsOut += [PSCustomObject]@{
                    text = [string]$w.Text
                    rect = @($wx1, $wy1, $wx2, $wy2)
                }
            }
            # Collapse spaces inserted by Windows OCR around CJK glyphs and fullwidth punctuation
            $cleanLine = ($line.Text -replace '(?<=[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef])\s+|\s+(?=[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef])', '').Trim()
            $linesOut += [PSCustomObject]@{
                text  = $cleanLine
                rect  = @([int][Math]::Round($minX), [int][Math]::Round($minY), [int][Math]::Round($maxX), [int][Math]::Round($maxY))
                words = $wordsOut
            }
        }
        @{
            status          = "ok"
            actual_language = $actualLang
            pixel_size      = @($pxW, $pxH)
            lines           = $linesOut
        } | ConvertTo-Json -Compress -Depth 6
    } finally {
        if ($null -ne $bitmap) { $bitmap.Dispose() }
        $stream.Dispose()
    }
} catch {
    @{
        status = "error"
        error  = $_.Exception.Message
        lines  = @()
    } | ConvertTo-Json -Compress -Depth 4
    exit 1
}
