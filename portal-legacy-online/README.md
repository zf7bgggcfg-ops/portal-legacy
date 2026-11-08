# PORTAL LEGACY — version en ligne

Cette version ajoute :
- comptes avec pseudo + mot de passe ;
- mots de passe hachés avec bcrypt (jamais stockés en clair) ;
- sessions sécurisées en cookie HTTP-only ;
- sauvegardes individuelles par compte ;
- base SQLite persistante ;
- limitation des tentatives de connexion ;
- interface de jeu adaptée au mobile.

## Lancer en local

Prérequis : Node.js 20 ou plus récent.

```bash
npm install
```

Définis un secret de session (au moins 32 caractères) puis lance :

```bash
# macOS / Linux
SESSION_SECRET="une-longue-chaine-aleatoire-de-plus-de-32-caracteres" npm start

# Windows PowerShell
$env:SESSION_SECRET="une-longue-chaine-aleatoire-de-plus-de-32-caracteres"
npm start
```

Ouvre ensuite http://localhost:3000.

## Publier sur Internet avec Render

1. Crée un compte Render et un dépôt GitHub.
2. Décompresse ce projet et envoie tout le contenu du dossier dans un dépôt GitHub.
3. Dans Render, choisis **New > Blueprint** et relie le dépôt.
4. Render détectera `render.yaml`. Vérifie le service `portal-legacy`, puis lance le déploiement.
5. Le service utilise un disque persistant monté sur `/var/data` pour conserver les comptes, sessions et sauvegardes lors des redémarrages.
6. Une fois le déploiement terminé, Render fournit une URL publique en `https://...onrender.com`.

**Important :** ce modèle Render utilise un service Starter avec disque persistant. Un hébergement statique gratuit type Netlify Drop ne suffit pas pour les comptes et les sauvegardes. Ne supprime pas le disque persistant, sinon les données SQLite qu'il contient seront perdues.

## Sécurité et limites

- Le site ne demande pas d'adresse e-mail ni de nom réel.
- Les pseudos sont uniques (3–20 caractères, lettres/chiffres/_).
- Les mots de passe font au moins 10 caractères et sont hachés avec bcrypt.
- Les sessions durent jusqu'à 7 jours et utilisent des cookies HTTP-only/SameSite Strict.
- La base ne stocke que le hash du mot de passe.
- Prévois des sauvegardes régulières du disque de données avant d'ouvrir le site à beaucoup de joueurs.
- Les comptes sont propres à ce site : ne réutilise pas un mot de passe personnel.
