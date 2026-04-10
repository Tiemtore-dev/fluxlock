# Guide Utilisateur — FluXlock

> Votre coffre-fort numérique personnel, protégé par de la cryptographie de nouvelle génération.

---

## Table des matières

1. [Présentation](#présentation)
2. [Installation](#installation)
3. [Premier démarrage](#premier-démarrage)
4. [Gestion des mots de passe](#gestion-des-mots-de-passe)
5. [Coffre-fort de fichiers](#coffre-fort-de-fichiers)
6. [Clés cryptographiques](#clés-cryptographiques)
7. [Partage sécurisé](#partage-sécurisé)
8. [Transfert entre appareils](#transfert-entre-appareils)
9. [Authentification à deux facteurs (2FA)](#authentification-à-deux-facteurs-2fa)
10. [Biométrie](#biométrie)
11. [Sauvegarde et restauration](#sauvegarde-et-restauration)
12. [Sécurité système](#sécurité-système)
13. [Journal d'audit](#journal-daudit)
14. [Paramètres](#paramètres)
15. [Réinitialisation du coffre](#réinitialisation-du-coffre)
16. [Questions fréquentes](#questions-fréquentes)

---

## Présentation

FluXlock est une application de bureau (et mobile) qui vous permet de :

- **Stocker vos mots de passe** de manière chiffrée
- **Protéger vos fichiers** sensibles dans un coffre-fort numérique
- **Gérer vos clés cryptographiques** (classiques et post-quantiques)
- **Transférer des données** entre vos appareils de façon sécurisée, sans passer par Internet
- **Détecter automatiquement** les tentatives de ransomware sur votre système

Toutes vos données sont chiffrées localement sur votre machine. Aucun serveur distant n'a accès à vos informations.

### Niveau de protection

FluXlock utilise des algorithmes de chiffrement parmi les plus robustes existants, y compris des algorithmes **post-quantiques** (résistants aux futurs ordinateurs quantiques) :

- Vos mots de passe sont chiffrés avec **ChaCha20-Poly1305** (standard utilisé par Google, Cloudflare, etc.)
- Votre mot de passe maître est transformé en clé de chiffrement via **Argon2id** (protection contre les attaques par force brute, même avec du matériel spécialisé)
- Les transferts utilisent un mélange de **SPAKE2** + **ML-KEM-768** (protection post-quantique)

---

## Installation

### macOS

1. Téléchargez le fichier `.dmg` depuis la page des releases
2. Ouvrez le fichier `.dmg`
3. Glissez FluXlock dans votre dossier Applications
4. Au premier lancement, faites clic droit → Ouvrir (nécessaire car l'application n'est pas sur l'App Store)

### Windows

1. Téléchargez le fichier `.msi` depuis la page des releases
2. Double-cliquez sur l'installeur
3. Suivez les instructions d'installation
4. FluXlock sera disponible dans le menu Démarrer

### Linux

1. Téléchargez le fichier `.AppImage` ou `.deb` depuis la page des releases
2. Pour `.AppImage` : rendez-le exécutable (`chmod +x FluXlock.AppImage`) puis lancez-le
3. Pour `.deb` : `sudo dpkg -i fluxlock_*.deb`

### Android

1. Téléchargez le fichier `.apk` depuis la page des releases
2. Activez "Sources inconnues" dans les paramètres de votre téléphone
3. Installez l'APK
4. FluXlock apparaîtra dans votre tiroir d'applications

---

## Premier démarrage

### Création de votre compte

Au premier lancement, FluXlock vous demande de créer un compte local :

1. **Email** : Saisissez votre adresse email (utilisée comme identifiant uniquement, aucun email n'est envoyé sans votre accord)
2. **Mot de passe maître** : Choisissez un mot de passe fort. C'est la **seule clé** pour accéder à toute vos données.

> **Important** : Si vous perdez votre mot de passe maître, il est **impossible** de récupérer vos données. FluXlock ne stocke pas votre mot de passe — il ne conserve que la clé de chiffrement dérivée.

### Recommandations pour le mot de passe maître

- **Minimum 12 caractères** (idéalement 16+)
- Mélangez lettres, chiffres et symboles
- Évitez les mots du dictionnaire et les informations personnelles
- Vous pouvez utiliser une **phrase de passe** : `le-chat-mange-3-souris-bleues!` est excellent

### Après la connexion

Une fois connecté, vous arrivez sur le **tableau de bord** qui affiche :

- Le nombre de mots de passe stockés
- Le nombre de fichiers chiffrés
- L'état de la sécurité de votre système
- Le statut de la biométrie et du 2FA

---

## Gestion des mots de passe

### Ajouter un mot de passe

1. Cliquez sur **Mots de passe** dans la barre latérale
2. Cliquez sur le bouton **+ Nouveau**
3. Remplissez les champs :
   - **Nom du site** : ex. "Gmail", "Netflix"
   - **Nom d'utilisateur** : votre identifiant pour ce site
   - **Mot de passe** : vous pouvez le saisir manuellement ou cliquer sur le dé pour en générer un aléatoirement
   - **URL** (optionnel) : l'adresse du site
   - **Notes** (optionnel) : informations supplémentaires
4. Cliquez sur **Enregistrer**

Le mot de passe est instantanément chiffré et stocké dans votre coffre.

### Consulter un mot de passe

1. Dans la liste des mots de passe, cliquez sur l'entrée souhaitée
2. Le mot de passe est affiché masqué (•••••)
3. Cliquez sur l'icône **œil** pour le révéler
4. Cliquez sur l'icône **copier** pour le copier dans le presse-papier

> Le presse-papier est **automatiquement vidé après 30 secondes** pour éviter les fuites accidentelles.

### Modifier un mot de passe

1. Ouvrez l'entrée du mot de passe
2. Cliquez sur **Modifier**
3. Apportez vos modifications
4. Cliquez sur **Enregistrer**

### Supprimer un mot de passe

1. Ouvrez l'entrée du mot de passe
2. Cliquez sur **Supprimer**
3. Confirmez la suppression

> La suppression est définitive. Si vous n'êtes pas sûr, pensez à faire une sauvegarde d'abord.

### Recherche

Utilisez la barre de recherche en haut de la page pour filtrer vos mots de passe par nom de site, nom d'utilisateur ou URL.

**Raccourci clavier** : `Cmd+K` (macOS) ou `Ctrl+K` (Windows/Linux) pour ouvrir la recherche rapide.

---

## Coffre-fort de fichiers

### Chiffrer un fichier

1. Cliquez sur **Fichiers** dans la barre latérale
2. Cliquez sur **+ Chiffrer un fichier**
3. Sélectionnez le fichier à protéger via le sélecteur de fichiers
4. FluXlock chiffre le fichier avec votre clé maître et le stocke dans le coffre

> Les fichiers volumineux sont chiffrés par blocs de 64 Ko (streaming), ce qui permet de traiter des fichiers de toute taille sans saturer la mémoire.

### Déchiffrer un fichier

1. Dans la liste des fichiers chiffrés, cliquez sur le fichier souhaité
2. Cliquez sur **Déchiffrer**
3. Choisissez l'emplacement de destination
4. Le fichier est déchiffré et exporté

> Les fichiers temporaires déchiffrés sont **automatiquement écrasés avec des zéros** puis supprimés lorsque vous vous déconnectez ou verrouillez l'application.

### Supprimer un fichier chiffré

1. Sélectionnez le fichier dans la liste
2. Cliquez sur **Supprimer**
3. Confirmez la suppression

---

## Clés cryptographiques

FluXlock vous permet de générer et gérer des paires de clés cryptographiques.

### Types de clés disponibles

| Type                 | Usage                                    | Résistance quantique |
| -------------------- | ---------------------------------------- | -------------------- |
| **Ed25519 / X25519** | Signatures et échange de clés classiques | Non                  |
| **ML-KEM-768**       | Encapsulation de clés (chiffrement)      | Oui (FIPS 203)       |
| **ML-DSA-65**        | Signatures numériques                    | Oui (FIPS 204)       |

### Générer une paire de clés

1. Cliquez sur **Clés** dans la barre latérale
2. Cliquez sur **+ Générer**
3. Choisissez le type : **Classique** (Ed25519/X25519) ou **Post-quantique** (ML-KEM-768/ML-DSA-65)
4. La paire de clés est générée et stockée

### Exporter une clé publique

1. Sélectionnez la paire de clés
2. Cliquez sur **Copier la clé publique**
3. Partagez-la avec votre correspondant

> Seule la clé publique peut être exportée. La clé privée ne quitte jamais le coffre.

---

## Partage sécurisé

### Partager un fichier

1. Allez dans **Partages** dans la barre latérale
2. Cliquez sur **Partager un fichier**
3. Sélectionnez le fichier à partager
4. Le fichier est chiffré et un lien de partage est généré

### Révoquer un partage

1. Dans la liste des partages actifs
2. Cliquez sur **Révoquer** à côté du partage
3. Le lien devient immédiatement inutilisable

---

## Transfert entre appareils

Le transfert P2P (pair-à-pair) vous permet de synchroniser des mots de passe et fichiers entre deux appareils sur le **même réseau local**, sans passer par Internet.

### Comment ça marche

1. Les deux appareils se découvrent automatiquement sur le réseau (via mDNS)
2. Un **code wormhole** (mot de passe à usage unique) sécurise la connexion
3. Les données sont chiffrées de bout en bout pendant le transfert
4. Aucune donnée en clair ne touche jamais le disque

### Envoyer des données

1. Allez dans **Transfert** dans la barre latérale
2. Cliquez sur **Créer une offre**
3. Sélectionnez ce que vous voulez envoyer (mots de passe ou fichiers)
4. Un **code wormhole** s'affiche (par exemple : `7-guitar-castle`)
5. Communiquez ce code à votre correspondant (verbalement, SMS, etc.)

### Recevoir des données

1. Allez dans **Transfert** dans la barre latérale
2. Cliquez sur **Recevoir**
3. Saisissez le **code wormhole** communiqué par l'expéditeur
4. La connexion s'établit automatiquement
5. Un **numéro de sécurité** s'affiche sur les deux appareils — vérifiez qu'ils correspondent
6. Acceptez le transfert

### Numéro de sécurité

Le numéro de sécurité (8 caractères hexadécimaux) est calculé à partir de la clé de session. Si un attaquant interceptait la connexion, les numéros seraient différents. **Vérifiez toujours ce numéro** avant d'accepter un transfert.

### Appareils de confiance

Vous pouvez ajouter des appareils dans votre liste de confiance pour simplifier les futurs transferts :

1. Après un transfert réussi, cliquez sur **Faire confiance à cet appareil**
2. L'appareil est signé avec une signature post-quantique (ML-DSA-65)
3. Les prochains transferts avec cet appareil seront automatiquement reconnus

Pour révoquer la confiance : allez dans **Transfert** → **Appareils de confiance** → **Révoquer**.

---

## Authentification à deux facteurs (2FA)

Le 2FA ajoute une couche de protection supplémentaire : même si quelqu'un connaît votre mot de passe maître, il ne pourra pas se connecter sans le code 2FA.

### Activer le TOTP

1. Allez dans **Sécurité** dans la barre latérale
2. Cliquez sur **Configurer la 2FA**
3. Scannez le QR code avec une application d'authentification (Google Authenticator, Authy, etc.)
4. Saisissez le code à 6 chiffres pour confirmer
5. Le 2FA est maintenant actif

### Se connecter avec le 2FA

1. Entrez votre email et mot de passe maître
2. Saisissez le code à 6 chiffres affiché dans votre application d'authentification
3. Le code change toutes les 30 secondes

### Désactiver le 2FA

1. Allez dans **Sécurité**
2. Cliquez sur **Désactiver la 2FA**
3. Confirmez avec votre mot de passe maître

> **Attention** : Sécurisez l'accès à votre application d'authentification. Si vous perdez votre téléphone sans backup des codes 2FA, vous pourriez perdre l'accès à votre coffre.

---

## Biométrie

Sur les plateformes compatibles, vous pouvez déverrouiller FluXlock avec votre empreinte digitale ou votre visage.

### Plateformes supportées

| Plateforme | Technologie                                        |
| ---------- | -------------------------------------------------- |
| macOS      | Touch ID (Secure Enclave)                          |
| Windows    | Windows Hello                                      |
| Android    | Empreinte / Reconnaissance faciale (TEE/StrongBox) |

### Activer la biométrie

1. Connectez-vous avec votre mot de passe maître
2. Allez dans **Paramètres** → **Biométrie**
3. Cliquez sur **Activer la biométrie**
4. Authentifiez-vous avec votre biométrie pour confirmer

### Limites de sécurité

- La biométrie **ne remplace pas** le mot de passe maître
- Au premier démarrage de l'application (ou après un redémarrage), le mot de passe maître est **toujours requis**
- Après 3 échecs biométriques, FluXlock demande le mot de passe maître
- La biométrie expire après 15 minutes d'inactivité

---

## Sauvegarde et restauration

### Créer une sauvegarde

1. Allez dans **Sauvegarde** dans la barre latérale
2. Cliquez sur **Créer une sauvegarde**
3. Choisissez l'emplacement de destination
4. La sauvegarde est créée (compressée et chiffrée)

> La sauvegarde contient vos mots de passe, fichiers et clés, le tout chiffré avec votre clé maître.

### Restaurer une sauvegarde

1. Allez dans **Sauvegarde**
2. Cliquez sur **Restaurer**
3. Sélectionnez le fichier de sauvegarde
4. Saisissez le mot de passe maître qui a été utilisé pour créer la sauvegarde
5. Les données sont restaurées

### Recherche automatique

FluXlock recherche automatiquement les fichiers de sauvegarde dans les emplacements standards (Bureau, Documents, Téléchargements) pour vous simplifier la restauration.

---

## Sécurité système

### Détection de ransomware

FluXlock surveille en continu votre système de fichiers et peut détecter :

- **Les extensions suspectes** : `.encrypted`, `.locked`, `.crypto`, `.ransom`, et 50+ autres
- **Les modifications rapides** : Plus de 15 fichiers modifiés en 10 secondes
- **Le chiffrement de masse** : Plus de 30 fichiers chiffrés en 30 secondes

Si une activité suspecte est détectée, FluXlock bascule automatiquement en **mode lecture seule** pour protéger vos données.

### Mode lecture seule

Quand le mode lecture seule est activé :

- Aucune modification ne peut être apportée au coffre
- Les données existantes restent accessibles en lecture
- Un administrateur peut désactiver le mode via **Sécurité système** → **Désactiver le mode lecture seule** (mot de passe requis)

### Tableau de bord sécurité

La page **Sécurité système** affiche :

- Le niveau de menace actuel (aucun, bas, moyen, élevé, critique)
- Les menaces actives détectées
- Les statistiques de surveillance fichiers
- L'état du mode lecture seule

---

## Journal d'audit

Chaque action importante dans FluXlock est enregistrée dans un journal signé numériquement.

### Consulter le journal

1. Allez dans **Sécurité** dans la barre latérale
2. Faites défiler jusqu'à la section **Journal d'audit**
3. Chaque entrée affiche : date, action, résultat

### Vérifier l'intégrité

1. Cliquez sur **Vérifier l'intégrité du journal**
2. FluXlock vérifie la chaîne de hachage et les signatures
3. Si tout est correct : "Intégrité vérifiée"
4. Si une entrée a été falsifiée : alerte immédiate

> Le journal utilise une chaîne de hachage SHA3-256 et des signatures ML-DSA-65 (post-quantiques). Il est techniquement impossible de modifier une entrée passée sans casser la chaîne.

---

## Paramètres

### Verrouillage automatique

1. Allez dans **Paramètres**
2. Sous **Auto-lock**, choisissez le délai d'inactivité (en minutes)
3. Après ce délai sans activité, FluXlock se verrouille automatiquement

> Le verrouillage efface la clé de chiffrement de la mémoire. Pour reprendre, vous devrez saisir votre mot de passe maître (ou utiliser la biométrie).

### Changer le mot de passe maître

1. Allez dans **Paramètres**
2. Cliquez sur **Changer le mot de passe maître**
3. Saisissez l'ancien mot de passe
4. Saisissez le nouveau mot de passe (deux fois)
5. Toutes vos données sont re-chiffrées avec la nouvelle clé

> Cette opération peut prendre quelques secondes si vous avez beaucoup de données.

---

## Réinitialisation du coffre

> **Attention** : Cette opération est irréversible. Toutes vos données seront définitivement effacées.

1. Allez dans **Réinitialiser** dans la barre latérale
2. Lisez les avertissements
3. Saisissez votre mot de passe maître pour confirmer
4. Cliquez sur **Réinitialiser le coffre**
5. Le coffre est vidé et vous pouvez repartir de zéro

---

## Questions fréquentes

### Que se passe-t-il si je perds mon mot de passe maître ?

Il est **impossible** de récupérer vos données sans le mot de passe maître. C'est une mesure de sécurité fondamentale : personne, pas même le développeur de FluXlock, ne peut déchiffrer vos données. Faites des sauvegardes régulières et conservez votre mot de passe maître en lieu sûr.

### Mes données sont-elles envoyées sur Internet ?

**Non.** Tout le chiffrement et le stockage se font localement sur votre appareil. La seule communication réseau possible est :

- Le transfert P2P (sur votre réseau local uniquement, et uniquement quand vous l'initiez)
- La vérification de mises à jour (optionnelle)

### Qu'est-ce que la cryptographie "post-quantique" ?

Les ordinateurs quantiques, lorsqu'ils seront suffisamment puissants, pourront casser certains algorithmes de chiffrement classiques (RSA, ECDH). FluXlock utilise des algorithmes **ML-KEM-768** et **ML-DSA-65**, standardisés par le NIST (l'organisme américain de normalisation) en 2024, qui résistent à ces attaques.

### Le transfert P2P est-il sûr ?

Oui. Le transfert utilise :

1. Un code wormhole (SPAKE2) pour authentifier les deux appareils sans jamais transmettre de mot de passe
2. Un échange de clés hybride (ML-KEM-768) résistant aux attaques quantiques
3. Un chiffrement de session ChaCha20-Poly1305 pour toutes les données échangées
4. Un numéro de sécurité vérifiable visuellement pour détecter toute interception

### Puis-je utiliser FluXlock sur plusieurs appareils ?

Oui, grâce au transfert P2P. Vous pouvez synchroniser vos mots de passe entre deux appareils sur le même réseau local. Il n'y a pas de synchronisation cloud automatique (par design, pour la sécurité).

### Comment fonctionne le verrouillage automatique ?

FluXlock utilise un double mécanisme :

1. Un timer JavaScript côté interface (vérifie l'activité souris/clavier)
2. Un heartbeat backend (vérifie l'activité IPC avec le moteur Rust)

Si aucune activité n'est détectée pendant le délai configuré, la clé de chiffrement est effacée de la mémoire et l'application se verrouille.

### Comment protège-t-il contre les ransomwares ?

FluXlock surveille en permanence votre système de fichiers :

- Il détecte les extensions typiques des ransomwares (`.encrypted`, `.locked`, etc.)
- Il surveille les pics de modifications fichiers (chiffrement de masse)
- En cas de menace détectée, il bascule en mode lecture seule pour protéger le coffre

### Où sont stockées mes données ?

| Plateforme | Emplacement                                  |
| ---------- | -------------------------------------------- |
| macOS      | `~/Library/Application Support/SecureVault/` |
| Windows    | `%LOCALAPPDATA%\SecureVault\`                |
| Linux      | `~/.local/share/SecureVault/`                |
| Android    | Répertoire privé de l'application            |

### Raccourcis clavier

| Raccourci      | Action                    |
| -------------- | ------------------------- |
| `Cmd/Ctrl + K` | Recherche rapide          |
| `Cmd/Ctrl + L` | Verrouiller l'application |
| `Cmd/Ctrl + N` | Nouvel élément            |
| `Escape`       | Fermer le dialogue actif  |

---

_FluXlock v2.0.0 — Coffre-fort numérique avec cryptographie post-quantique_
