import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ArrowLeftRight, Archive, ChevronRight, Files, KeyRound, ShieldCheck, Fingerprint } from 'lucide-react'
import { passwords, files, keys, security } from '../lib/vault-service'
import { WorkspacePage } from '../design-system/layouts'

export default function DashboardPage() {
  const entries = useQuery({ queryKey: ['passwords'], queryFn: passwords.list })
  const documents = useQuery({ queryKey: ['secureFiles'], queryFn: files.list })
  const cryptographicKeys = useQuery({ queryKey: ['secureKeys'], queryFn: keys.list })
  const events = useQuery({ queryKey: ['securityEvents'], queryFn: security.getEvents })
  const alerts = events.data?.filter((event) => event.severity === 'critical' || event.severity === 'warning').length

  return (
    <WorkspacePage title="Votre coffre">
      <div className="dashboard-grid">
        <section aria-labelledby="dashboard-content">
          <h2 id="dashboard-content">Contenu du coffre</h2>
          <ul className="dashboard-index">
            <li><Link to="/passwords">
              <KeyRound size={19} aria-hidden="true" />
              <span>Mots de passe</span>
              <small>{entries.isError ? 'Indisponible' : entries.data ? entries.data.length : '…'}</small>
              <ChevronRight size={16} aria-hidden="true" />
            </Link></li>
            <li><Link to="/files">
              <Files size={19} aria-hidden="true" />
              <span>Fichiers chiffrés</span>
              <small>{documents.isError ? 'Indisponible' : documents.data ? documents.data.length : '…'}</small>
              <ChevronRight size={16} aria-hidden="true" />
            </Link></li>
            <li><Link to="/keys">
              <Fingerprint size={19} aria-hidden="true" />
              <span>Clés cryptographiques</span>
              <small>{cryptographicKeys.isError ? 'Indisponible' : cryptographicKeys.data ? cryptographicKeys.data.length : '…'}</small>
              <ChevronRight size={16} aria-hidden="true" />
            </Link></li>
          </ul>
        </section>

        <section aria-labelledby="dashboard-actions">
          <h2 id="dashboard-actions">Actions du coffre</h2>
          <ul className="dashboard-index">
            <li><Link to="/transfer"><ArrowLeftRight size={19} aria-hidden="true" /><span>Transférer des données</span><ChevronRight size={16} aria-hidden="true" /></Link></li>
            <li><Link to="/backup"><Archive size={19} aria-hidden="true" /><span>Sauvegarder ou restaurer</span><ChevronRight size={16} aria-hidden="true" /></Link></li>
            <li><Link to={alerts ? '/security' : '/system-security'}><ShieldCheck size={19} aria-hidden="true" /><span>Consulter la sécurité</span>
              {alerts ? <small className="dashboard-warning">{alerts} alerte{alerts > 1 ? 's' : ''}</small> : null}
              <ChevronRight size={16} aria-hidden="true" />
            </Link></li>
          </ul>
        </section>
      </div>
    </WorkspacePage>
  )
}
