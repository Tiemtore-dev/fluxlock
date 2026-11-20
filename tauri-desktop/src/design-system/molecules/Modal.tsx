import { useEffect, useId, useRef, type ReactNode } from 'react'
import { X } from 'lucide-react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  width?: number
}

export function Modal({ open, onClose, title, children, width = 520 }: ModalProps) {
  const ref = useRef<HTMLDialogElement>(null)
  const headingId = useId()

  useEffect(() => {
    const dialog = ref.current
    if (!open || !dialog) return
    dialog.showModal()
    return () => dialog.close()
  }, [open])

  return (
    <dialog ref={ref} className="modal-panel workspace-modal" style={{ maxWidth: width }} aria-labelledby={headingId}
      onCancel={(event) => { event.preventDefault(); onClose() }}>
      {open && <>
        <header className="modal-header">
          <h2 id={headingId}>{title}</h2>
          <button type="button" className="workspace-close" aria-label="Fermer" onClick={onClose}><X size={20} aria-hidden="true" /></button>
        </header>
        <div className="modal-body">{children}</div>
      </>}
    </dialog>
  )
}
