import { execFileSync } from 'node:child_process'
import { mkdirSync, copyFileSync, readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
const root = fileURLToPath(new URL('..', import.meta.url))
const repo = path.resolve(root, '..')
execFileSync(process.execPath, [path.join(repo, 'tauri-desktop/node_modules/typescript/bin/tsc'), '-p', path.join(root, 'tsconfig.json')], { stdio: 'inherit' })
execFileSync('cargo', ['build', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--manifest-path', path.join(repo, 'autofill-protocol/Cargo.toml')], { stdio: 'inherit', env: { ...process.env, CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS: '-C link-arg=-zstack-size=4194304' } })
mkdirSync(path.join(root, 'dist'), { recursive: true })
for (const name of ['popup.html', 'popup.css', 'manifest.json']) copyFileSync(path.join(root, name), path.join(root, 'dist', name))
copyFileSync(path.join(repo, 'tauri-desktop/src/design-system/tokens.css'), path.join(root, 'dist/tokens.css'))
mkdirSync(path.join(root, 'dist/icons'), { recursive: true })
for (const size of [32, 128]) copyFileSync(path.join(repo, `tauri-desktop/src-tauri/icons/${size}x${size}.png`), path.join(root, `dist/icons/${size}.png`))
copyFileSync(path.join(repo, 'autofill-protocol/target/wasm32-unknown-unknown/release/fluxlock_autofill_protocol.wasm'), path.join(root, 'dist/noise.wasm'))
// Chromium key fixes the unpacked development identity. The release store ID
// must be verified and explicitly supplied to the host installer on publishing.
const manifest = JSON.parse(readFileSync(path.join(root, 'dist/manifest.json'), 'utf8'))
if (process.env.FLUXLOCK_EXTENSION_PUBLIC_KEY) manifest.key = process.env.FLUXLOCK_EXTENSION_PUBLIC_KEY
writeFileSync(path.join(root, 'dist/manifest.json'), JSON.stringify(manifest, null, 2) + '\n')
const nativeHost = process.env.FLUXLOCK_EXTENSION_TEST_PROFILE === '1' ? 'com.fluxlock.browser.test' : 'com.fluxlock.browser'
writeFileSync(path.join(root, 'dist/config.js'), `export const nativeHost = ${JSON.stringify(nativeHost)};\n`)
console.log('Extension construite dans browser-extension/dist (aucune installation système effectuée).')
