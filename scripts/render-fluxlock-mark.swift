import AppKit
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

// The mark uses a 144-unit construction grid. The same geometry is rendered
// at each target size, including the separate Android foreground layer.
let paper = CGColor(red: 0.902, green: 0.914, blue: 0.863, alpha: 1)
let ink = CGColor(red: 0.141, green: 0.161, blue: 0.137, alpha: 1)
let graphite = CGColor(red: 0.098, green: 0.102, blue: 0.094, alpha: 1)

enum Direction: String, CaseIterable {
    case folio = "Feuillet"
    case interval = "Intervalle"
    case margin = "Lisière"

    func outline() -> CGPath {
        let path = CGMutablePath()
        func move(_ x: CGFloat, _ y: CGFloat) { path.move(to: CGPoint(x: x, y: y)) }
        func line(_ x: CGFloat, _ y: CGFloat) { path.addLine(to: CGPoint(x: x, y: y)) }
        func curve(_ x: CGFloat, _ y: CGFloat, _ a: CGFloat, _ b: CGFloat, _ c: CGFloat, _ d: CGFloat) {
            path.addCurve(to: CGPoint(x: x, y: y), control1: CGPoint(x: a, y: b), control2: CGPoint(x: c, y: d))
        }

        switch self {
        case .folio:
            move(34, 109)
            line(34, 71)
            curve(69, 34, 34, 48, 48, 34)
            line(110, 34)
            line(99, 50)
            line(69, 50)
            curve(50, 71, 57, 50, 50, 58)
            line(50, 97)
            path.closeSubpath()

            move(60, 67)
            line(99, 67)
            line(88, 83)
            line(60, 83)
            path.closeSubpath()
        case .interval:
            move(33, 81)
            line(33, 58)
            curve(53, 38, 33, 45, 41, 38)
            line(107, 38)
            line(91, 54)
            line(58, 54)
            curve(49, 63, 52, 54, 49, 58)
            line(49, 65)
            path.closeSubpath()

            move(111, 62)
            line(111, 86)
            curve(91, 106, 111, 98, 103, 106)
            line(37, 106)
            line(53, 90)
            line(86, 90)
            curve(95, 81, 92, 90, 95, 86)
            line(95, 78)
            path.closeSubpath()
        case .margin:
            move(38, 110)
            line(70, 36)
            line(90, 36)
            line(58, 110)
            path.closeSubpath()

            move(77, 110)
            line(100, 57)
            line(114, 70)
            line(97, 110)
            path.closeSubpath()
        }
        return path
    }
}

enum Background {
    case tile, circle, transparent
}

func drawIcon(_ context: CGContext, direction: Direction, in area: CGRect, background: Background = .tile) {
    context.saveGState()
    context.translateBy(x: area.minX, y: area.maxY)
    context.scaleBy(x: area.width / 144, y: -area.height / 144)
    context.setFillColor(paper)
    switch background {
    case .tile:
        context.addPath(CGPath(roundedRect: CGRect(x: 0, y: 0, width: 144, height: 144), cornerWidth: 30, cornerHeight: 30, transform: nil))
        context.fillPath()
    case .circle:
        context.fillEllipse(in: CGRect(x: 0, y: 0, width: 144, height: 144))
    case .transparent:
        break
    }
    context.setFillColor(ink)
    context.addPath(direction.outline())
    context.fillPath()
    context.restoreGState()
}

func png(_ path: URL, width: Int, height: Int, draw: (CGContext) -> Void) {
    let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
    let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8,
                            bytesPerRow: width * 4, space: colorSpace,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.setAllowsAntialiasing(true)
    context.setShouldAntialias(true)
    draw(context)
    let destination = CGImageDestinationCreateWithURL(path as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, context.makeImage()!, nil)
    precondition(CGImageDestinationFinalize(destination))
}

func label(_ text: String, in context: CGContext, x: Int, y: Int, size: CGFloat, bold: Bool = false) {
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
    (text as NSString).draw(at: CGPoint(x: x, y: y), withAttributes: [
        .font: NSFont.systemFont(ofSize: size, weight: bold ? .semibold : .regular),
        .foregroundColor: NSColor(cgColor: graphite)!,
    ])
    NSGraphicsContext.restoreGraphicsState()
}

let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let output = root.appendingPathComponent("build-output/import-csv", isDirectory: true)
let android = root.appendingPathComponent("tauri-desktop/src-tauri/gen/android/app/src/main/res", isDirectory: true)

func renderTile(_ at: URL, size: Int, background: Background = .tile) {
    png(at, width: size, height: size) {
        drawIcon($0, direction: .folio, in: CGRect(x: 0, y: 0, width: size, height: size), background: background)
    }
}

renderTile(root.appendingPathComponent("docs/images/logo.png"), size: 1024)
renderTile(root.appendingPathComponent("docs/images/logo-256.png"), size: 256)
renderTile(root.appendingPathComponent("tauri-desktop/public/fluxlock-mark.png"), size: 256)

let densities: [(String, Int, Int)] = [
    ("mdpi", 48, 108), ("hdpi", 72, 162), ("xhdpi", 96, 216),
    ("xxhdpi", 144, 324), ("xxxhdpi", 192, 432)
]
for (density, legacySize, adaptiveSize) in densities {
    let directory = android.appendingPathComponent("mipmap-\(density)", isDirectory: true)
    renderTile(directory.appendingPathComponent("ic_launcher.png"), size: legacySize)
    renderTile(directory.appendingPathComponent("ic_launcher_round.png"), size: legacySize, background: .circle)
    renderTile(directory.appendingPathComponent("ic_launcher_foreground.png"), size: adaptiveSize, background: .transparent)
}

png(output.appendingPathComponent("FluXlock-etude-logo.png"), width: 1200, height: 592) { context in
    context.setFillColor(CGColor(red: 0.957, green: 0.953, blue: 0.929, alpha: 1))
    context.fill(CGRect(x: 0, y: 0, width: 1200, height: 592))
    label("FluXlock", in: context, x: 55, y: 510, size: 35, bold: true)
    label("Étude du signe et réduction à 24 px", in: context, x: 55, y: 470, size: 18)
    for (column, direction) in Direction.allCases.enumerated() {
        let x = 55 + column * 369
        label(direction.rawValue, in: context, x: x, y: 392, size: 24, bold: true)
        drawIcon(context, direction: direction, in: CGRect(x: x, y: 146, width: 213, height: 213))
        context.setFillColor(graphite)
        context.fill(CGRect(x: x, y: 55, width: 290, height: 57))
        drawIcon(context, direction: direction, in: CGRect(x: x + 15, y: 71, width: 24, height: 24))
        drawIcon(context, direction: direction, in: CGRect(x: x + 55, y: 67, width: 32, height: 32))
        drawIcon(context, direction: direction, in: CGRect(x: x + 104, y: 63, width: 40, height: 40), background: .circle)
    }
}
