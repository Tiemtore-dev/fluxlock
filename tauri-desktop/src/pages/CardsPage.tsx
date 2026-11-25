import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, CreditCard, Eye, EyeOff, Copy } from 'lucide-react'
import { paymentCards, type PaymentCard } from '../lib/vault-service'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { SearchBar, Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { useClipboard } from '../hooks/useClipboard'

export default function CardsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const copy = useClipboard()
  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [title, setTitle] = useState('')
  const [cardholderName, setCardholderName] = useState('')
  const [cardNumber, setCardNumber] = useState('')
  const [expMonth, setExpMonth] = useState('')
  const [expYear, setExpYear] = useState('')
  const [cvv, setCvv] = useState('')
  const [notes, setNotes] = useState('')

  const [decryptedMap, setDecryptedMap] = useState<Map<number, { card_number: string; cvv: string }>>(new Map())
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (decryptedMap.size === 0) return
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setDecryptedMap(new Map()), 60_000)
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [decryptedMap.size])

  const { data: cards = [], isLoading } = useQuery({
    queryKey: ['payment-cards'],
    queryFn: paymentCards.list,
  })

  const createMut = useMutation({
    mutationFn: () =>
      paymentCards.create({
        title,
        cardholder_name: cardholderName,
        card_number: cardNumber,
        exp_month: expMonth,
        exp_year: expYear,
        cvv,
        notes,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['payment-cards'] })
      setShowModal(false)
      setTitle(''); setCardholderName(''); setCardNumber(''); setExpMonth(''); setExpYear(''); setCvv(''); setNotes('')
      toast('Carte bancaire enregistrée (contrôle Luhn validé)', 'success')
    },
    onError: (err) => toast('Erreur : ' + String(err), 'error'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => paymentCards.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['payment-cards'] })
      toast('Carte bancaire supprimée', 'success')
    },
    onError: (err) => toast('Erreur : ' + String(err), 'error'),
  })

  const toggleRevealCard = async (card: PaymentCard) => {
    if (decryptedMap.has(card.id)) {
      setDecryptedMap((prev) => {
        const next = new Map(prev)
        next.delete(card.id)
        return next
      })
      return
    }
    try {
      const secret = await paymentCards.decryptSecret(card.id)
      setDecryptedMap((prev) => new Map(prev).set(card.id, secret))
    } catch (err) {
      toast('Erreur déchiffrement : ' + String(err), 'error')
    }
  }

  const copyCardNumber = async (card: PaymentCard) => {
    try {
      const cached = decryptedMap.get(card.id) ?? (await paymentCards.decryptSecret(card.id))
      copy(cached.card_number)
      toast('Numéro de carte copié — effacé dans 30 s', 'success')
    } catch (err) {
      toast('Erreur déchiffrement : ' + String(err), 'error')
    }
  }

  const filtered = cards.filter((c) => {
    const q = search.toLowerCase()
    return (
      c.title.toLowerCase().includes(q) ||
      c.cardholder_name.toLowerCase().includes(q) ||
      c.brand.toLowerCase().includes(q) ||
      c.last4.includes(q)
    )
  })

  return (
    <WorkspacePage
      title="Cartes bancaires"
      description={`${cards.length} carte${cards.length === 1 ? '' : 's'} protégée${cards.length === 1 ? '' : 's'} (ChaCha20-Poly1305 + AAD)`}
      actions={
        <Button icon={Plus} onClick={() => setShowModal(true)}>
          Nouvelle carte
        </Button>
      }
    >
      <section className="workspace-panel workspace-stack" aria-labelledby="cards-list">
        <h2 id="cards-list">Cartes enregistrées</h2>
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher par titre, titulaire, réseau ou 4 derniers chiffres…" />
        {isLoading ? (
          <p role="status" className="workspace-label">
            <Spinner size={18} /> Chargement…
          </p>
        ) : filtered.length === 0 ? (
          <p className="workspace-empty">Aucune carte bancaire enregistrée.</p>
        ) : (
          <ul className="workspace-list">
            {filtered.map((card) => {
              const revealed = decryptedMap.get(card.id)
              return (
                <li key={card.id} className="workspace-row">
                  <div className="workspace-row-copy">
                    <strong>{card.title}</strong>
                    <span>
                      <Badge>{card.brand}</Badge> · {card.cardholder_name} · Exp. {card.exp_month}/{card.exp_year}
                    </span>
                    <span className="font-mono">
                      {revealed ? `${revealed.card_number} (CVV : ${revealed.cvv})` : `•••• •••• •••• ${card.last4}`}
                    </span>
                  </div>
                  <div className="workspace-actions">
                    <Button
                      variant="secondary"
                      size="sm"
                      icon={revealed ? EyeOff : Eye}
                      onClick={() => void toggleRevealCard(card)}
                    >
                      {revealed ? 'Masquer' : 'Révéler'}
                    </Button>
                    <Button variant="secondary" size="sm" icon={Copy} onClick={() => void copyCardNumber(card)}>
                      Copier PAN
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      icon={Trash2}
                      aria-label={`Supprimer ${card.title}`}
                      onClick={() => {
                        if (confirm(`Supprimer « ${card.title} » ?`)) deleteMut.mutate(card.id)
                      }}
                    />
                  </div>
                </li>
              )
            })}
          </ul>
        )}
      </section>

      <Modal open={showModal} onClose={() => setShowModal(false)} title="Nouvelle carte bancaire">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            createMut.mutate()
          }}
          className="flex flex-col gap-4"
        >
          <Input label="Libellé de la carte" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ex: Visa Premier Pro" required />
          <Input label="Titulaire (cc-name)" value={cardholderName} onChange={(e) => setCardholderName(e.target.value)} placeholder="JEAN DUPONT" required />
          <Input label="Numéro de carte (cc-number — validé Luhn)" value={cardNumber} onChange={(e) => setCardNumber(e.target.value)} placeholder="4532 0151 1283 0366" required />
          <div className="grid grid-cols-3 gap-3">
            <Input label="Mois (MM)" value={expMonth} onChange={(e) => setExpMonth(e.target.value)} placeholder="08" required />
            <Input label="Année (AAAA)" value={expYear} onChange={(e) => setExpYear(e.target.value)} placeholder="2029" required />
            <Input label="CVV / CVC" type="password" value={cvv} onChange={(e) => setCvv(e.target.value)} placeholder="123" required />
          </div>
          <Input label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Plafond, banque…" />
          <div className="flex gap-3 pt-2">
            <Button type="submit" fullWidth icon={CreditCard} loading={createMut.isPending}>
              Chiffrer et enregistrer
            </Button>
            <Button type="button" variant="secondary" fullWidth onClick={() => setShowModal(false)}>
              Annuler
            </Button>
          </div>
        </form>
      </Modal>
    </WorkspacePage>
  )
}
