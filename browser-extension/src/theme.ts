// Runs before styles, using the same .dark selector as the desktop app.
if (location.protocol === 'chrome-extension:') document.documentElement.dataset.extensionPopup = 'true'
const systemTheme = matchMedia('(prefers-color-scheme: dark)')
const applySystemTheme = () => document.documentElement.classList.toggle('dark', systemTheme.matches)
applySystemTheme()
systemTheme.addEventListener('change', applySystemTheme)
