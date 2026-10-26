# Guide Utilisateur — FluXlock

> Votre coffre-fort numérique personnel, protégé par de la cryptographie de nouvelle génération.

---

## Table des matières

1. [Présentation](#présentation)
2. [Installation](#installation)
3. [Premier démarrage](#premier-démarrage)
4. [Tableau de bord](#tableau-de-bord)
5. [Gestion des mots de passe](#gestion-des-mots-de-passe)
6. [Coffre-fort de fichiers](#coffre-fort-de-fichiers)
7. [Clés cryptographiques](#clés-cryptographiques)
8. [Transfert entre appareils](#transfert-entre-appareils)
9. [Sécurité système](#sécurité-système)
10. [Sauvegarde et restauration](#sauvegarde-et-restauration)
11. [Paramètres](#paramètres)
12. [Réinitialisation du coffre](#réinitialisation-du-coffre)
13. [Questions fréquentes](#questions-fréquentes)

---

## Présentation

FluXlock est une application de bureau et mobile qui vous permet de :

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

1. Téléchargez le fichier `.dmg` depuis la [page des releases](https://github.com/Tiemtore-dev/fluxlock/releases/latest)
2. Ouvrez le fichier `.dmg`
3. Glissez FluXlock dans votre dossier Applications
4. Au premier lancement, faites clic droit → **Ouvrir** (nécessaire car l'application n'est pas signée Apple)

### Windows

1. Téléchargez le fichier `_x64-setup.exe` depuis la [page des releases](https://github.com/Tiemtore-dev/fluxlock/releases/latest)
2. Lancez l'installeur
3. Suivez les instructions à l'écran

### Linux

1. Téléchargez le fichier `.deb`, `.rpm` ou `.AppImage` selon votre distribution depuis la [page des releases](https://github.com/Tiemtore-dev/fluxlock/releases/latest)
2. Pour `.deb` : `sudo dpkg -i FluXlock_*.deb`
3. Pour `.rpm` : `sudo rpm -i FluXlock-*.rpm`
4. Pour `.AppImage` : rendez le fichier exécutable (`chmod +x`) et lancez-le

### Android

1. Téléchargez le fichier `.apk` depuis la [page des releases](https://github.com/Tiemtore-dev/fluxlock/releases/latest)
2. Autorisez l'installation depuis des sources inconnues si nécessaire
3. Installez et ouvrez l'application

---

## Premier démarrage

### Création du compte

Au premier lancement, FluXlock vous demande de créer un compte local :

1. **Nom d'utilisateur** : choisissez un identifiant (il sera affiché dans l'interface)
2. **Email** : votre adresse email (utilisée pour l'identification)
3. **Mot de passe maître** : choisissez un mot de passe **d'au moins 12 caractères**. Un indicateur de force vous aide à évaluer sa robustesse

> **Important** : Ce mot de passe est la seule clé d'accès à votre coffre-fort. Il n'est stocké nulle part et ne peut pas être récupéré. Si vous le perdez, vous perdez l'accès à toutes vos données.

> **Note** : Chaque appareil ne peut avoir qu'un seul compte utilisateur.

### Connexion

Après la création du compte, vous pourrez vous connecter avec :

- **Email + mot de passe maître** : la méthode classique
- **Biométrie** : Touch ID (macOS), Windows Hello, ou capteur Android — si vous l'avez activée dans les paramètres
- **Passkey** : connexion par clé cryptographique Ed25519 — si vous l'avez configurée

Si vous échouez plusieurs fois, un **délai progressif** s'applique (protection anti-brute-force) et peut aller jusqu'à 2 minutes entre les tentatives.

---

## Tableau de bord

Le tableau de bord est la page d'accueil de FluXlock. Il affiche quatre statistiques en un coup d'œil :

| Carte | Description |
|:---|:---|
| **Mots de passe** | Nombre total de mots de passe stockés dans votre coffre |
| **Fichiers chiffrés** | Nombre de fichiers protégés dans le coffre-fort |
| **Sécurité** | Indique « Élevé » si aucune menace n'est détectée, « Alerte » sinon |
| **Alertes** | Nombre d'événements de sécurité de niveau élevé |

---

## Gestion des mots de passe

Depuis la barre latérale, cliquez sur **Mots de passe**.

### Ajouter un mot de passe

1. Cliquez sur le bouton **+ Nouveau** (ou utilisez le raccourci `⌘N` / `Ctrl+N`)
2. Remplissez les champs :
   - **Titre** : le nom du service (ex. « Gmail », « Netflix »)
   - **Nom d'utilisateur** : votre identifiant sur ce service
   - **Mot de passe** : votre mot de passe (ou cliquez sur le bouton **Générer** pour en créer un)
   - **URL** : l'adresse du site (optionnel)
   - **Notes** : informations supplémentaires (optionnel)
   - **Catégorie** : pour organiser vos mots de passe (optionnel)
3. Cliquez sur **Créer**

### Générer un mot de passe fort

Lors de la création ou la modification d'un mot de passe, utilisez le générateur intégré :

- **Longueur** : ajustez la longueur avec le curseur (défaut : 20 caractères)
- **Majuscules** : A-Z
- **Minuscules** : a-z
- **Chiffres** : 0-9
- **Symboles** : !@#$%...

Cliquez sur le bouton de **régénération** pour obtenir un nouveau mot de passe aléatoire.

### Rechercher et filtrer

- Utilisez la **barre de recherche** pour trouver un mot de passe par titre, nom d'utilisateur ou URL
- Filtrez par **catégorie** en cliquant sur les tags disponibles

### Actions rapides

- **Copier** : cliquez sur le mot de passe pour le copier dans le presse-papiers
- **Révéler** : cliquez sur l'icône œil pour afficher le mot de passe en clair
- **Modifier** : cliquez sur l'icône crayon pour éditer les informations
- **Supprimer** : cliquez sur l'icône corbeille (avec confirmation)

### Import / Export CSV

- **Importer** : importez des mots de passe depuis un fichier CSV (format auto-détecté, compatible Chrome, Firefox, Bitwarden, etc.). Un écran de prévisualisation vous permet de choisir pour chaque entrée si vous souhaitez l'importer, l'ignorer ou écraser l'existant.
- **Exporter** : exportez vos mots de passe en CSV. Votre mot de passe maître est requis pour autoriser l'export (sécurité).

> **Mode lecture seule** : si le système de détection de ransomware a détecté une menace, les modifications sont temporairement bloquées. Vous pourrez uniquement consulter vos mots de passe.

---

## Coffre-fort de fichiers

Depuis la barre latérale, cliquez sur **Fichiers**.

### Chiffrer un fichier

1. Cliquez sur **Chiffrer un fichier**
2. Sélectionnez le fichier à protéger via le sélecteur de fichiers de votre système
3. Une barre de progression s'affiche pendant le chiffrement
4. Une fois terminé, le fichier apparaît dans la liste

Le chiffrement se fait par **flux** (streaming), ce qui permet de traiter des fichiers volumineux sans surcharger la mémoire.

### Déchiffrer et récupérer un fichier

1. Cliquez sur le bouton **Déchiffrer** à côté du fichier
2. Choisissez l'emplacement de sauvegarde
3. Le fichier est déchiffré et enregistré à l'endroit choisi

### Partager un fichier chiffré

1. Cliquez sur l'icône de partage à côté d'un fichier
2. Saisissez l'**email du destinataire**
3. Choisissez la **durée d'expiration** du partage (en jours)
4. Un lien de partage sécurisé est généré

Vous pouvez gérer vos partages actifs depuis la page **Mes Partages** (accessible via le menu), où vous pouvez voir la durée restante et révoquer un partage à tout moment.

### Informations affichées

Chaque fichier affiche :
- Le **nom** du fichier original
- Le **type** de fichier (icône adaptée : image, vidéo, audio, archive, document, etc.)
- La **taille** du fichier
- La **date** de chiffrement

---

## Clés cryptographiques

Depuis la barre latérale, cliquez sur **Clés crypto**.

### Types de clés supportés

| Type | Usage |
|:---|:---|
| **SSH** | Connexion à des serveurs distants |
| **API** | Tokens et clés d'accès aux APIs |
| **GPG** | Chiffrement et signature d'emails |
| **Encryption** | Clés de chiffrement génériques |

### Générer une clé

1. Cliquez sur **Générer une clé**
2. Choisissez un **nom** et un **type**
3. La paire de clés (publique + privée) est générée et stockée dans le coffre

### Importer une clé

1. Cliquez sur **Importer**
2. Collez les données de la clé et renseignez un nom et un type

### Consulter une clé

1. Cliquez sur l'icône œil pour **révéler** les données de la clé
2. Pour les clés SSH, la clé publique et la clé privée sont affichées séparément
3. Utilisez le bouton **Copier** pour copier une clé dans le presse-papiers

> **Sécurité** : les clés déchiffrées sont automatiquement effacées de la mémoire après **60 secondes** d'inactivité.

---

## Transfert entre appareils

Depuis la barre latérale, cliquez sur **Transfert**.

Le transfert P2P permet d'envoyer des mots de passe, fichiers et clés entre deux appareils **sur le même réseau local**, sans passer par Internet.

### Envoyer des données

1. Allez dans l'onglet **Envoyer**
2. Choisissez le type de données à envoyer : **Mots de passe**, **Fichiers** ou **Clés**
3. Sélectionnez les éléments à transférer
4. FluXlock génère un **code wormhole** (ex. `7-guitar-violin`)
5. Communiquez ce code au destinataire

### Recevoir des données

1. Allez dans l'onglet **Recevoir**
2. Saisissez le **code wormhole** reçu de l'expéditeur
3. Les données sont transférées et re-chiffrées automatiquement dans votre coffre

### Vérification de sécurité

Lors du transfert, un **numéro de sécurité** et un **identicon visuel** (grille de couleurs 3×3) sont affichés des deux côtés. Vérifiez qu'ils correspondent pour garantir que personne n'intercepte le transfert.

### Appareils de confiance

L'onglet **Pairs** affiche les appareils avec lesquels vous avez déjà effectué un transfert. Vous pouvez :
- Voir la liste des appareils de confiance
- Supprimer un appareil de confiance

---

## Sécurité système

Depuis la barre latérale, cliquez sur **Sécurité**.

### Surveillance en temps réel

FluXlock surveille votre système de fichiers en temps réel. Le panneau de sécurité affiche :

- **Niveau de menace** : None / Low / Medium / High / Critical
- **Mode lecture seule** : activé automatiquement en cas de menace élevée
- **Menaces actives** : liste des comportements suspects détectés

### Statistiques du système de fichiers

- Nombre total d'événements surveillés
- Modifications, créations, suppressions et renommages de fichiers
- Nombre d'**extensions suspectes** détectées (plus de 50 types de ransomware connus)
- Nombre de **changements rapides** (indicateur de chiffrement massif)

### Actions disponibles

- **Activer/Désactiver la surveillance** du système de fichiers
- **Désactiver le mode lecture seule** (nécessite votre mot de passe maître, en cas de faux positif)

---

## Sauvegarde et restauration

Depuis la barre latérale, cliquez sur **Backup**.

### Créer une sauvegarde

1. Saisissez votre **mot de passe maître**
2. Cliquez sur **Créer un backup**
3. Le fichier de sauvegarde chiffré (`.svbackup`) est créé
4. Sur Android, la sauvegarde est automatiquement copiée dans le dossier Documents

### Restaurer une sauvegarde

1. Cliquez sur **Restaurer** à côté d'une sauvegarde existante, ou importez un fichier `.svbackup`
2. Saisissez le **mot de passe maître** qui a été utilisé lors de la création de la sauvegarde
3. Confirmez la restauration
4. L'application redémarre automatiquement après la restauration

### Informations de sauvegarde

Chaque backup affiche :
- Le **nom d'utilisateur** et l'**appareil** d'origine
- Le **nombre de mots de passe** et de **fichiers** inclus
- La **date de création**
- La **version** de l'application au moment du backup

---

## Paramètres

Depuis la barre latérale, cliquez sur **Paramètres**.

### Apparence

- **Thème** : basculer entre le mode sombre et le mode clair
- **Couleur d'accentuation** : choisissez parmi plusieurs thèmes de couleur (défaut, Emerald, Violet, Rose, Amber, Sapphire, Crimson, etc.)

### Sécurité

- **Verrouillage automatique** : activez/désactivez le verrouillage automatique après une période d'inactivité
- **Délai de verrouillage** : de 1 à 60 minutes d'inactivité avant le verrouillage

### Biométrie

Activez la connexion par empreinte digitale ou reconnaissance faciale :

1. Cliquez sur **Activer la biométrie**
2. Lisez les informations de sécurité
3. Cochez la case de consentement
4. Confirmez avec votre mot de passe maître
5. Authentifiez-vous avec votre empreinte/visage

Plateformes supportées :

| Plateforme | Technologie |
|:---|:---|
| macOS | Touch ID (Secure Enclave) |
| Windows | Windows Hello |
| Android | TEE / StrongBox Keymaster |

### Passkey (Ed25519)

Alternative à la biométrie, la passkey utilise une clé cryptographique Ed25519 :

1. Cliquez sur **Activer la passkey**
2. Confirmez avec votre mot de passe maître
3. La clé est générée et stockée dans le Keychain/Keystore de votre appareil

### Synchronisation entre appareils

Jumelez deux appareils FluXlock pour qu'ils se reconnaissent automatiquement lors des transferts :

1. Sur l'appareil A, cliquez sur **Lancer le jumelage** → un code s'affiche
2. Sur l'appareil B, saisissez ce code et cliquez sur **Rejoindre**
3. Les appareils sont maintenant jumelés

Vous pouvez voir les appareils jumelés et les supprimer si nécessaire.

### Mode isolation

Active des protections supplémentaires qui restreignent les opérations sensibles (utile si vous suspectez une compromission).

### Journal signé

Active la signature cryptographique de chaque entrée du journal d'audit, garantissant que les logs ne peuvent pas être falsifiés.

---

## Réinitialisation du coffre

> **⚠️ Action irréversible**

La réinitialisation supprime définitivement **toutes** vos données :
- Tous vos mots de passe
- Tous vos fichiers chiffrés
- Toutes vos clés cryptographiques
- Votre compte et vos paramètres
- L'historique de sécurité complet
- La base de données intégrale

Pour réinitialiser :

1. Allez dans les **Paramètres** ou accédez à la page de réinitialisation
2. Lisez les avertissements
3. Tapez exactement **`SUPPRIMER TOUT`** dans le champ de confirmation
4. Saisissez votre **mot de passe maître**
5. Confirmez la réinitialisation

Après la réinitialisation, vous serez redirigé vers la page de création de compte.

---

## Questions fréquentes

### Que se passe-t-il si je perds mon mot de passe maître ?

Malheureusement, il est **impossible de récupérer** votre mot de passe maître. FluXlock est conçu sur le principe du « zéro connaissance » : personne, pas même l'application, ne connaît votre mot de passe. C'est pourquoi nous recommandons fortement de créer des sauvegardes régulières et de conserver votre mot de passe maître dans un endroit sûr.

### Mes données sont-elles envoyées sur Internet ?

**Non.** Toutes vos données restent sur votre appareil. Les transferts entre appareils se font uniquement sur votre réseau local (Wi-Fi), sans passer par aucun serveur distant.

### Que fait le mode lecture seule ?

Le mode lecture seule est activé automatiquement par FluXlock lorsqu'un comportement suspect est détecté sur votre système (par exemple, un ransomware qui tente de chiffrer massivement vos fichiers). Dans ce mode, vous pouvez consulter vos données mais pas les modifier. Vous pouvez le désactiver manuellement avec votre mot de passe maître si c'est un faux positif.

### L'application se met-elle à jour automatiquement ?

Oui. FluXlock vérifie automatiquement les nouvelles versions via GitHub et vous propose de les installer. Les mises à jour sont signées pour garantir leur authenticité.

### Puis-je utiliser FluXlock sur plusieurs appareils ?

Oui. Installez FluXlock sur chaque appareil, créez un compte sur chacun, puis utilisez la fonction **Transfert** pour envoyer vos données d'un appareil à l'autre. Vous pouvez également jumeler vos appareils dans les **Paramètres** pour simplifier les transferts futurs.
