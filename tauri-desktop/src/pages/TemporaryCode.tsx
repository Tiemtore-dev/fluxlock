import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { Button } from '../design-system/atoms'

export function TemporaryCode({ code }: { code: string }) {
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')

  async function copy() {
    try {
      await writeText(code)
      setCopyState('copied')
    } catch {
      setCopyState('failed')
    }
  }

  return (
    <div className="temporary-code">
      <code>{code}</code>
      <Button variant="secondary" icon={copyState === 'copied' ? Check : Copy} onClick={copy}>
        {copyState === 'copied' ? 'Code copié' : 'Copier le code'}
      </Button>
      {copyState === 'failed' && <p role="alert">Sélectionnez le code et copiez-le manuellement.</p>}
    </div>
  )
}
