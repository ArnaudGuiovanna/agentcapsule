# Plan d’implémentation des contextes externes (corpus)

**Objectif.** Un administrateur ajoute un contexte de connaissances à ses agents : documents, présentations, tableurs, audios, vidéos. Les sources viennent d’un dépôt GitHub ou GitLab. La plateforme les convertit en Markdown et en données structurées, construit un index et un sommaire (`INDEX.md`), puis publie le tout comme une **version immuable**. Comme une release de harness, cette version est montée **en lecture seule dans toutes les VM qui en ont besoin, sans être copiée** : une image par hôte, un lien dur par jail. Les agents lisent ce contexte localement, sans réseau.

**Nom de la ressource.** Le CLI utilise déjà `context` pour les contextes de connexion (`agentcapsule context add|use`). La ressource s’appelle donc **`corpus`** dans l’API, le CLI et l’ABI de l’invité : `/v1/corpora`, `agentcapsule corpus …`, `/corpus/<nom>` dans la VM. Ce document dit « contexte » ou « corpus » indifféremment.

**Contraintes.**
- Les traitements de la plateforme tournent **sur CPU**.
- Toute inférence (OCR, transcription, description d’images, résumés, embeddings) passe par les API des fournisseurs via la passerelle LLM, et non par des modèles locaux.
- Les gros contextes sont construits **en asynchrone**.
- Le cœur reste sans logique métier ([product.md §5](product.md#5-out-of-scope-for-p0)). Un traitement propre à un harness, par exemple pédagogique, passe par un « enrichisseur » externe (lot 9).

Les routes, formats et commandes ci-dessous sont des propositions de conception. Les décisions marquées **D-C** sont à acter dans l’ADR 023 avant le lot 1.

## Suivi du chantier

**20 novembre 2026 · Non démarré.** Le plan s’appuie sur l’état du dépôt à `321143b` (release `v0.0.1`).

| Lot | État |
|---|---|
| 0. Contrats, ADR 023, modèle Quint | Fait (ADR 023, brouillon OpenAPI `openapi/drafts/corpora.yaml`, COR-001 à COR-009 en `not met`, `spec/corpus_lifecycle.qnt`) |
| 1. Formats et paquet | Non démarré |
| 2. Passerelle multimodale | Non démarré |
| 3. Sources Git | Non démarré |
| 4. Disques supplémentaires et montage dans l’invité | Non démarré |
| 5. Agent de construction | Non démarré |
| 6. Publication, liaison et cache | Non démarré |
| 7. CLI et documentation | Non démarré |
| 8. SDK et adaptateur | Non démarré |
| 9. Enrichisseurs | Non démarré |
| 10. Recette | Non démarré |

## 1. Parcours à livrer

| Qui | Action | Résultat visible |
|---|---|---|
| Auteur du contenu (formateur, documentaliste) | Range ses supports dans un dépôt Git avec un fichier `agentcapsule-corpus.yaml`, et vérifie localement avec `agentcapsule corpus lint` | Liste des fichiers retenus, des types reconnus, des fichiers ignorés et une estimation des volumes à traiter |
| Administrateur de l’organisation | Enregistre un jeton Git en lecture seule et déclare le corpus (`corpus create … --git … --ref main`) | Corpus créé, rattaché au dépôt et à la branche, jeton stocké chiffré et jamais réaffiché |
| Administrateur | Lance une construction (`corpus build`) | Une construction asynchrone, épinglée sur un commit, avec sa progression par étape et par fichier |
| Administrateur | Relit le résultat : rapport, `INDEX.md`, fichiers en échec, essai sur un agent de test (`corpus-build try`) | Il sait ce qui a été extrait, avec quelle confiance et pour quel coût, et peut interroger un agent avant de publier. Les corrections se font dans le dépôt, puis on reconstruit. |
| Administrateur | Publie la construction (`corpus-build publish --version 3`) | Une version immuable `finance-l3:3`, identifiée par son empreinte |
| Administrateur | Ajoute le corpus à un template et lance un rollout | Au prochain boot, chaque agent du déploiement voit `/corpus/finance/` en lecture seule. Une seule image est présente sur l’hôte. |
| Agent (harness) | Lit `/corpus/finance/INDEX.md`, cherche dans `search/fts.sqlite` et ouvre les sections utiles | Des réponses sourcées avec un localisateur (page, diapositive, timecode), sans appel réseau |
| Administrateur | Publie `finance-l3:4`, migre le template, puis déprécie la version 3 | Les agents passent à la version 4 au boot suivant. La version 3 disparaît du cache quand plus personne ne l’utilise. |

## 2. Point de départ et architecture

| Domaine | À réutiliser | À construire |
|---|---|---|
| Format d’image | `harnesspkg.BuildRootfs` (ext4 reproductible : UUID déterministe, sans journal, horodatages fixes), `CheckRootfs`, `InspectRootfs` (debugfs confiné), `checksums.json` ([harnesspkg](../internal/harnesspkg/package.go)) | `internal/corpuspkg` : manifeste `corpus.yaml`, validation, extraction confinée du lot de revue |
| Récupération des sources | Client sortant d’`ociregistry` : `addrpolicy`, règles par hôte, `blob_hosts`, redirections bornées, jeton retiré quand l’hôte change ([client.go](../internal/ociregistry/client.go)) ; boucle `HarnessImporter` : bail, tentatives, backoff ([registry.go](../internal/worker/registry.go)) | Un récupérateur Git dans le worker (l’API ne lie aucun importeur : `TestAPILinksNoRuntimeWorkerOrGuestCode`) : archive par commit, objets LFS par empreinte |
| Secrets | Scellement des clés de fournisseur LLM (AES-GCM, AAD organisation, ressource et génération), rotation, désactivation ([llm_providers.go](../internal/controlplane/llm_providers.go)) | Des « identifiants de source » d’organisation, sur le même modèle |
| Exécution non fiable | MicroVM sans carte réseau, canal plateforme, passerelle LLM, budgets, volume LUKS | Un « agent de construction » caché par organisation, qui reçoit des disques supplémentaires (sources, LFS, sortie) |
| Distribution | Lien dur dans la jail, disque en lecture seule, `LOCK_SH` des disques en lecture seule partagés (patch Firecracker), cache `<root>/releases/sha256/…`, `Refill`, `Evict`, `-collect-garbage` | Le même mécanisme pour `corpus.ext4`, avec plusieurs disques par VM et une éviction limitée aux images épinglées |
| Liaison | Templates `name@N`, `validateTemplate`, rollouts avec canari, `Enrollment`, `ChangeAgentRelease` appliqué au boot suivant | Des corpus dans `TemplateSpec`, `agent_corpora`, une route d’épinglage par agent |
| Invité | `MountHarnessRoot`, chroot, fichiers de boot stricts de l’initrd (`AppendBootConfig`) | ABI `agentcapsule-guest/2` (point de montage `/corpus`), fichier de boot `corpora.json`, contrôle de l’UUID de chaque disque |
| Suivi | Ressource asynchrone à états (`harness_imports`), `operation wait --type`, concentrateur SSE du [plan streaming](plan-streaming.md) (lot 4) | Une ressource `corpus-builds` avec états, compteurs par fichier et rapport |

### 2.1 Chaîne complète

```
dépôt Git ──HTTPS (worker, règles d'hôte)──► archive.tar.gz + objets LFS (octets opaques, empreintes)
                                                │ disques bruts en lecture seule
                                                ▼
                          agent de construction (microVM sans NIC, CPU)
                          extraction ▸ rendu ▸ découpe audio
                          OCR ▸ transcription ▸ vision ▸ résumés ▸ embeddings ──► passerelle LLM (fournisseur)
                          assemblage ▸ index ▸ mkfs.ext4 ──► disque de sortie
                                                │
worker : CheckRootfs + debugfs confiné (stat, extraction du lot de revue) + sha256 ──► cache hôte
                                                │ revue, essai, publication
                                                ▼
            corpus-release finance-l3:3 ──► template ──► rollout ──► /corpus/finance/ (ro) dans N VM
```

**L’hôte ne lit jamais le contenu.**
- Le worker télécharge des octets opaques, vérifie des empreintes et les présente comme disques bruts.
- Tout décodage (tar, gzip, PDF, vidéo) a lieu dans la microVM.
- La règle REG-007 / RUN-010 (« the host never runs a package’s content ») est étendue aux sources de corpus et à leurs pièges de test.

## 3. Formats

### 3.1 Manifeste du dépôt (`agentcapsule.corpus-source/v1`)

Le fichier `agentcapsule-corpus.yaml` est versionné avec les sources : le contexte se gère comme du code.

```yaml
schema: agentcapsule.corpus-source/v1
title: "Finance d’entreprise — L3"
language: fr
include: ["cours/**", "videos/**", "donnees/**"]
exclude: ["**/brouillons/**"]
processing:
  ocr: auto                 # auto | always | never (pages sans texte natif)
  transcription: {alias: transcription-fr}
  vision: {alias: vision, describe_figures: true}
  summaries: {alias: resume}
  embeddings: {alias: embed} # optionnel
documents:                   # métadonnées optionnelles par fichier
  - path: cours/chap1.pdf
    title: "Chapitre 1 — Valeur temps de l’argent"
    tags: [actualisation, VAN]
corrections:                 # remplace la vue Markdown générée d’un document
  - path: videos/seance2.mp4
    markdown: corrections/seance2.md
```

Les alias désignent des alias LLM de l’organisation : budgets, droits et prix s’appliquent comme pour un agent ([api/llm.md](api/llm.md)).

### 3.2 Contenu publié (`agentcapsule.corpus/v1`)

```
/corpus/<montage>/
  corpus.json          ← nom, version, commit source, version du constructeur, langues,
                         nombre de documents, tokens totaux et par document, modalités
  INDEX.md             ← sommaire global : collections, documents, résumé de 2 à 3 lignes,
                         chemins ; budget cible ≤ 8 000 tokens
  topics/*.md          ← index thématiques (notion → sections)
  glossary.md          ← termes extraits et définition sourcée
  docs/<id>/
    doc.json           ← représentation canonique : éléments typés, ordre de lecture,
                         page/coordonnées ou timecode, confiance d’extraction, ID stables
    README.md          ← fiche : résumé, plan, métadonnées, chemin source
    part-001.md …      ← vue Markdown découpée, ancres vers les ID d’éléments
    pages/*.webp       ← pages, diapositives, images clés vidéo
    data/*.csv         ← données restées données, avec leur fiche .md
  search/fts.sqlite    ← passages contextualisés (FTS5), à ouvrir avec mode=ro&immutable=1
  search/vectors.*     ← optionnel, modèle d’embedding déclaré dans corpus.json
  report.json          ← rapport de construction (fichier, statut, avertissements, coûts)
```

Les originaux ne sont pas copiés dans l’image. Les citations renvoient au chemin et au commit sources. Le client peut construire le lien vers la forge.

### 3.3 Paquet sur l’hôte

Le paquet est le miroir de celui du harness, dans `<root>/corpora/sha256/<hex>/` :
- `corpus.yaml` (schéma `agentcapsule.corpus/v1`, nom, version, empreinte de construction, commit source, base `agentcapsule-guest/2`) ;
- `checksums.json` ;
- `corpus.ext4`.

Le format est ext4, construit avec les mêmes options reproductibles que `BuildRootfs`, et son UUID est fixé par le worker avant la construction (D-C2).

## 4. Décisions à acter (ADR 023)

| ID | Question | Options | Recommandation |
|---|---|---|---|
| D-C1 | Nom de la ressource | `corpus` ; `knowledge` ; renommer les contextes de connexion du CLI | **`corpus`**. Il est court, juste et ne casse aucune commande publiée en `v0.0.1`. |
| D-C2 | Système de fichiers de l’image | ext4 ; squashfs ; EROFS | **ext4** en première version : il réutilise `CheckRootfs`, l’inspection debugfs et la construction reproductible. squashfs existe dans le noyau invité, mais l’hôte ne sait pas l’inspecter et `unsquashfs` est un piège REG-007. EROFS demande un nouveau noyau (`CONFIG_EROFS_FS` absent de `runtime/guest/microvm-linux-6.1.config`). La compression est à reconsidérer plus tard. |
| D-C3 | Où tourne la construction | (a) agent caché par organisation, avec la harness `agentcapsule-corpus-builder` ; (b) nouveau type de VM « job » sans volume ; (c) sur l’hôte dans un bac à sable | **(a)**. Il réutilise tout le chemin agent : canal plateforme, passerelle et budgets de l’organisation, capacités, sommeil. Son volume chiffré sert de cache de conversion, ce qui rend les reconstructions incrémentales. (b) oblige à réécrire `capsule-init`, qui ouvre toujours LUKS, et le placement. (c) viole REG-007. |
| D-C4 | Récupération Git | `git clone` sur l’hôte ; archives de la forge par commit ; clone dans la VM | **Archives de la forge** (API GitHub `tarball/{sha}`, API GitLab `repository/archive.tar.gz?sha=`), récupérées par le worker comme octets opaques. Un clone sur l’hôte ferait analyser des packfiles non fiables, et la VM n’a pas de réseau. |
| D-C5 | Fichiers volumineux (vidéos) | Git LFS ; stockage objet ; dépôt OCI | **Git LFS, en deux phases.** (1) L’agent de construction lit l’archive et renvoie la liste des pointeurs LFS (`oid`, taille). (2) Le worker télécharge chaque objet via l’API batch LFS, vérifie son sha256 (`oid`) et les présente en disque brut, sans rien analyser. Un dépôt OCI (`corpus source --oci`) servira plus tard aux sources locales, en réutilisant `Fetcher`. |
| D-C6 | Intégrité dans l’invité | Empreinte à l’insertion dans le cache ; dm-verity ; fs-verity | **Empreinte à l’insertion, vérification mémorisée par inode, taille et mtime.** Re-hacher plusieurs Go à chaque résolution d’agent, comme `harnessImage` le fait pour le harness, coûterait trop. dm-verity (absent du noyau invité) est à ajouter en P2. |
| D-C7 | Corrections humaines | Base de correctifs dans la plateforme ; corrections dans le dépôt | **Dans le dépôt** (`corrections:` du manifeste), puis reconstruction. La traçabilité est celle de Git, sans état caché dans la plateforme. |
| D-C8 | Portée | Organisation ; plateforme (partagé entre organisations) | **Organisation** en première version, conformément à l’isolation par défaut. Un corpus de plateforme partagé reste une question P2. |
| D-C9 | Distribution multi-hôtes | Cache local seulement ; publication OCI vers un registre approuvé et `Refill` | **Cache local** en première version, car le produit est mono-hôte d’abord ([product.md](product.md)). Lot P2 : pousser le paquet signé en artefact OCI et réutiliser `Fetcher` et `Refill`. |

## 5. Conception par composant

### 5.1 Identifiants de source (lot 3)

- **Routes.**
  - `POST /v1/source-credentials` : `{name, kind: github|gitlab, host, secret}`, scope `corpus:manage`.
  - Également `rotate`, `disable` et `list` : métadonnées seules, le secret n’est jamais renvoyé.
- **Stockage.** Le secret est scellé comme une clé de fournisseur LLM : AES-GCM, clé dérivée de la clé de reçu de l’installation, libellé `agentcapsule.source-credential.v1`, AAD organisation, identifiant et génération. Il n’est déchiffré que dans le worker, au moment de la récupération.
- **Jeton attendu.** Un jeton en **lecture seule** : `contents:read` pour un fine-grained PAT GitHub, `read_repository` pour un jeton de projet GitLab. La documentation le recommande et l’API refuse un hôte qui ne correspond pas à la règle d’hôte.

### 5.2 Règles d’hôtes de sources (lot 3)

- **Configuration.** La configuration du worker gagne une section `corpus.sources.rules`, sur le modèle des règles de registre : `host`, préfixes de `repositories`, `archive_hosts` (par exemple `codeload.github.com`), `lfs_hosts` (stockages des objets LFS), `local`.
- **Hôtes publics.** Adresses publiques seulement, contrôlées après résolution DNS par `addrpolicy`. Au plus 3 redirections vers les hôtes déclarés. L’en-tête `Authorization` est retiré dès que l’hôte change.
- **GitLab auto-hébergé sur une adresse interne.** Il faut une autorisation explicite de l’opérateur, comme `llm.allowed_internal_providers` pour les fournisseurs LLM, sinon il est refusé en production (`preflight_linux.go:29`).

### 5.3 Récupération (lot 3)

1. **Résolution du ref.** Le ref est résolu en SHA de commit : API `commits/{ref}` de GitHub ou de GitLab. La construction est **épinglée** sur ce SHA.
2. **Archive.** L’archive est téléchargée en flux, dans la limite d’une taille plafond (2 GiB par défaut). Le worker calcule son sha256 et l’écrit dans `<root>/corpus-staging/<build>/source.bin`, complété jusqu’à un multiple de 4 KiB. La taille exacte est transmise à l’agent de construction.
3. **Phase LFS (D-C5).**
   - L’agent de construction renvoie les pointeurs par pages : la complétion est limitée à 32 KiB.
   - Le worker appelle l’API batch LFS, télécharge chaque objet, vérifie `sha256 == oid` et concatène les objets dans `lfs.bin`. Un index `{oid, offset, length}` accompagne l’invocation suivante.
   - La taille totale est plafonnée (20 GiB par défaut).
4. **Boucle et reprise.** La boucle `CorpusFetcher` suit le modèle de `HarnessImporter` : bail, tentatives (5), backoff, refus sous pression de stockage d’images (`refuseUnderImagePressure`).
   - Les objets LFS déjà vérifiés sont conservés pendant la construction : une reprise ne retélécharge que ce qui manque.

### 5.4 Disques supplémentaires et montage dans l’invité (lot 4)

Ce lot sert à la fois à l’agent de construction (disques sources et sortie) et aux agents consommateurs (corpus).

- **Runtime (`internal/runtime/firecracker_linux.go`, `prepare`).**
  - Une liste ordonnée de disques supplémentaires remplace le cas particulier du disque harness :
    - corpus : `is_read_only: true`, cache `Unsafe` ;
    - sources : `is_read_only: true` ;
    - sortie : `is_read_only: false`, fichier creux préalloué.
  - Au plus **4 corpus par VM**, plus les disques de construction.
  - **Pas de copie silencieuse.** `linkOrCopy` copie aujourd’hui si le cache et les jails sont sur des systèmes de fichiers différents (EXDEV). Pour un corpus, c’est un **refus** : contrôle au préflight du worker, plus une erreur explicite.
  - **Débit.** `DriveLimits` gagne un champ `Corpus`, avec une rafale initiale plafonnée (256 MiB, et non la taille de l’image). Le tableau d’ADR 012 est à mettre à jour.
- **Fichier de boot.**
  - Nouveau fichier strict `etc/capsule/corpora.json` dans l’initrd (`AppendBootConfig`) : `[{index, mount, uuid}]`.
  - Le boot record du harness (FD 3, 4 096 octets, champs inconnus refusés par Go et par Python) **ne change pas**, sinon tous les harness existants casseraient.
  - Le harness découvre ses corpus en listant `/corpus/`.
- **`capsule-init`.**
  - Pour chaque entrée, il lit le superbloc du disque `/dev/vd<index>` et **vérifie l’UUID attendu**. Cela protège de tout décalage d’ordre entre disques ; aujourd’hui `HarnessDevice="/dev/vdb"` est codé en dur.
  - Il monte ensuite en `ro,nosuid,nodev,noexec,noatime` sur `/corpus/<mount>` dans la racine du harness, ou dans la racine de l’initramfs pour un harness intégré.
- **ABI.**
  - `agentcapsule-guest/2` ajoute le point de montage `/corpus` à `harnesspkg.MountPoints`, `HarnessMountPoints`, `addMountPoints` et au contrôle d’`InspectRootfs`.
  - `Validate` accepte les bases 1 et 2.
  - Un template ou un agent ne peut lier un corpus qu’à une release de base 2.
- **Images système.** Les images système gagnent une colonne `features` (migration). Une image dont le `capsule-init` sait monter des corpus déclare `corpus.mount`, et `validateTemplate` l’exige. Un ancien `capsule-init` ignorerait silencieusement `corpora.json`.

### 5.5 Agent de construction (lot 5)

- **Agent système.** Un agent système par organisation (`kind: corpus-builder`) : non découvrable, non affectable, invisible des quotas d’agents de l’organisation mais compté dans la capacité de l’hôte.
  - Il est créé à la première construction et mis en sommeil par sa politique d’inactivité.
  - Son volume chiffré (2 GiB par défaut, extensible) sert de **cache de conversion**, indexé par `sha256(fichier) + version du constructeur + options`.
  - Ses invocations sont émises par un compte de service interne de l’organisation.
- **Harness `agentcapsule-corpus-builder`.**
  - C’est un paquet OCI signé, construit par le module Dagger, de base `agentcapsule-guest/2`.
  - Outils CPU sans modèle local :
    - extraction de texte PDF et rendu des pages (poppler) ;
    - conversions DOCX, PPTX et ODT (LibreOffice sans interface, pandoc) ;
    - tableurs en CSV ;
    - audio et vidéo (ffmpeg : extraction, découpe, images clés par détection de changement de plan) ;
    - SQLite FTS5 ;
    - e2fsprogs.
  - LibreOffice peut faire dépasser `max_harness_mib` (1 024 MiB par défaut) : il faut soit relever ce plafond pour cette release, soit prévoir une image allégée (à mesurer au lot 5).
- **Inférence**, uniquement via la passerelle (lot 2) :
  - OCR des pages sans texte natif ;
  - transcription horodatée des segments audio (découpés par ffmpeg pour rester sous la limite d’un message du canal) ;
  - description des figures par un modèle vision via `/v1/llm/forward` (les images passent déjà) ;
  - résumés, `INDEX.md`, index thématiques et glossaire ;
  - préfixes de contexte des passages ;
  - embeddings (optionnels).
- **Protocole.** Trois invocations JSON successives par construction, chacune `working` puis complétée :
  1. `scan` : liste des fichiers et pointeurs LFS, estimation des volumes et des coûts ;
  2. `convert` : conversion fichier par fichier, avec reprise sur cache ;
  3. `package` : assemblage, index, `mkfs.ext4 -d` sur le disque de sortie avec l’UUID imposé.

  La progression remonte à la fin de chaque phase. Une fois le [plan streaming](plan-streaming.md) livré (lot 3), elle remontera en continu sous forme d’événements `step` par fichier.
- **Contrôles du worker au retour.**
  - Il tronque le disque de sortie à la taille déclarée (bornée par l’allocation).
  - Il passe `CheckRootfs`, puis l’inspection debugfs confinée : présence de `corpus.json`, `INDEX.md` et `search/fts.sqlite`, absence de fichiers spéciaux.
  - Il calcule le sha256, puis déplace l’image dans le cache.
  - Le **lot de revue** (`INDEX.md`, `report.json`, `README.md` des documents, plafonné à 8 MiB) est extrait par debugfs confiné. C’est une extension à `dump` de la liste des appels autorisés du bac à sable. Il est stocké scellé, en segments, comme les pièces jointes, et lisible par l’API.
- **Cycle de vie.** Une construction peut être annulée ; ses fichiers de staging et sa sortie sont alors purgés. Durée maximale : 24 h. Une seule construction à la fois par organisation, par défaut.

### 5.6 Publication, liaison, cache (lot 6)

- **Tables (migrations 0056 et suivantes).**
  - `corpora` : organisation, nom, source Git, identifiant de source.
  - `corpus_builds` : état, SHA, version du constructeur, compteurs, coûts, codes d’erreur.
  - `corpus_releases` : nom, version, empreinte, octets, `enabled`, `deprecated_at`.
  - `agent_corpora` : agent, release, montage, position.
  - `corpus_audit`.
  - Les nouveaux codes d’erreur et actions d’audit passent par des contraintes CHECK, donc par des migrations.
- **États d’une construction.** `QUEUED → FETCHING → SCANNING → FETCHING_LFS → CONVERTING → PACKAGING → REVIEW → PUBLISHED`. Issues alternatives : `FAILED`, `CANCELED`, `EXPIRED` (revue non publiée après 30 jours, puis purge).
- **Publication.**
  - `POST /v1/corpus-builds/{id}/publish {version}` crée `name:version`, immuable.
  - Une version déjà prise par une autre empreinte est refusée (`version_conflict`, comme pour les imports).
  - `deprecate` empêche toute nouvelle liaison ; les agents épinglés continuent de fonctionner.
- **Essai avant publication.** `POST /v1/corpus-builds/{id}/try {agent}` lie une construction en `REVIEW` à un agent désigné de l’organisation, au prochain boot. L’administrateur peut ainsi interroger un harness ordinaire (Pi par exemple) sur le contenu avant de publier.
- **Liaison.**
  - `TemplateSpec` gagne `corpora: [{name, version, mount}]`.
  - `validateTemplate` vérifie, avec `FOR SHARE`, que chaque release est active, de la même organisation et compatible avec la base du harness et avec les `features` de l’image système.
  - `Enrollment`, `RolloutStep`, `SetRolloutProfile` et la persistance `HostAgent` transportent les empreintes des corpus.
  - Route directe : `POST /v1/agents/{id}/corpora`, appliquée au boot suivant, comme `agent release`.
- **Cache et éviction.**
  - Ne sont conservées que les images **épinglées** sur l’hôte : par un agent, une cible de rollout ouverte, une construction en revue ou un essai.
  - L’éviction actuelle garderait toutes les releases actives sur tous les hôtes, ce qui est trop coûteux en Go.
  - Il faut des équivalents corpus de `HarnessImagesInUse` et `HarnessImagesInUseAt`, ainsi que l’immuabilité de `RegisterProvisioned` et `ReplaceHarness`.
- **Quotas (ADR 021).** `corpus_bytes` (releases et constructions en revue) et `corpus_builds_concurrent` (1). Les coûts d’inférence sont imputés aux budgets de l’organisation par les alias du manifeste.
- **Droits.**
  - Nouvelle action et nouveau scope `corpus:manage`, accordés aux propriétaires et administrateurs de l’organisation.
  - Lecture des métadonnées : `corpus:read`.
  - Matrice [rbac.md](api/rbac.md) et `auditedRoutes` mises à jour.
  - Pas d’incrément de `policy_version` : la liaison d’un corpus n’est pas une règle d’autorisation, à l’image de `agent release`.

### 5.7 Passerelle multimodale (lot 2)

Les routes de la passerelle s’étendent au-delà de la conversation. Elles servent aussi aux harness, par exemple pour les embeddings de requête :

| Route du canal | Dialecte amont | Unité de comptage |
|---|---|---|
| `/v1/llm/embed` | OpenAI `embeddings` | tokens d’entrée |
| `/v1/llm/transcribe` | OpenAI `audio/transcriptions` (la passerelle compose le multipart à partir d’un corps JSON base64) | secondes d’audio |
| `/v1/llm/ocr` | Mistral `ocr` (fournisseur `openai_compatible` qui déclare cette capacité) | pages |

- Chaque alias déclare les capacités de son modèle (`chat`, `embed`, `transcribe`, `ocr`, `vision`). Une route non déclarée est refusée avec `capability_denied`.
- Les prix par unité étendent `alias prices` ([ADR 011](adr/011-llm-access-and-cost-budgets.md)).
- La limite de 1 MiB par message du canal impose des segments audio et des pages d’environ 700 KiB après encodage. C’est le constructeur qui découpe.
- Réservation, règlement, `outcome_unknown` et rejeu suivent les règles de `/v1/llm/complete`.
- La qualification réelle porte sur Ollama (embeddings) et sur un fournisseur hébergé (transcription et OCR), à choisir avec l’opérateur.

### 5.8 Enrichisseurs (lot 9, P1 du chantier)

- **Principe.** Un enrichisseur est un harness ordinaire (paquet OCI signé), autorisé par l’administrateur de l’organisation. Il lit une construction en `REVIEW` montée en lecture seule et écrit une image d’extension sur un disque de sortie.
- **Publication.** La release regroupe alors l’image de base et ses extensions. Chaque image est un disque, et une extension se monte sur `/corpus/<mount>/ext/<enrichisseur>/`, un répertoire réservé par le constructeur.
- **Exemple.** Un tuteur pédagogique peut en tirer `ext/<nom>/notions.json` et `exercices.json` une seule fois par cours, au lieu de le faire dans chaque VM d’apprenant.
- **Cœur inchangé.** La plateforme ne connaît que le mécanisme, jamais la sémantique.

## 6. Lots, dépendances et critères de sortie

| Lot | Travaux | Critère de sortie |
|---|---|---|
| **0. Contrats et modèle** | ADR 023 (D-C1 à D-C9). Brouillons OpenAPI. Nouvelle famille d’exigences COR-001 et suivantes dans [product.md §4](product.md) (import Git, construction asynchrone, revue, publication immuable, montage partagé, isolation, inférence par la passerelle), avec leurs lignes dans [acceptance.md](acceptance.md). Section « Corpora » de la [ROADMAP](../ROADMAP.md). Modèle `spec/corpus_lifecycle.qnt` avec les invariants `publishedIsImmutable`, `bootsOnlyBoundCorporaOfItsOrganization`, `bindingChangesAtBootOnly`, `buildPublishesAtMostOnce`, `gcNeverRemovesPinned`, déclaré dans `spec/projections.md`. | Typecheck et invariants Quint verts. Validation OpenAPI et `check-acceptance.py` verts avec les lignes en `not met`. |
| **1. Formats et paquet** | Spécifications `agentcapsule.corpus-source/v1` et `agentcapsule.corpus/v1` (nouvelle page `docs/corpus.md`, à créer). Paquet `internal/corpuspkg` : manifeste strict, empreintes, construction ext4 reproductible partagée avec `harnesspkg`, inspection. Commandes locales `corpus init DIR` et `corpus lint DIR` (sans API). | `corpus lint` reconnaît chaque type, signale les fichiers ignorés et estime les volumes. Deux constructions d’un même arbre donnent la même empreinte. |
| **2. Passerelle multimodale** | Routes `embed`, `transcribe`, `ocr`. Capacités par alias, prix par unité, réservation et règlement, faux fournisseurs de test, qualification réelle. | Tests PG de comptage pour chaque unité ; une coupure donne `outcome_unknown` réconciliable. Exécution réelle sur au moins un fournisseur pour chaque route. |
| **3. Sources Git** | Identifiants de source (scellement, rotation), règles d’hôtes, `CorpusFetcher` (résolution du SHA, archive, LFS par empreinte, staging, reprise), plafonds, pression de stockage. Extension de `TestTheHostNeverRunsWhatAPackageHolds` (pièges `tar`, `gzip`, `git`, `ffmpeg`, `pdftotext`, `soffice`) et de `workerStarts`. | Archive d’un dépôt public et d’un dépôt privé GitHub et GitLab, épinglée sur son SHA. Un objet LFS altéré est refusé. Redirection vers un hôte non déclaré refusée. Aucun programme lancé sur l’hôte. |
| **4. Disques et montage** | Liste de disques supplémentaires, `DriveLimits.Corpus`, refus EXDEV, `corpora.json`, contrôle de l’UUID, ABI `agentcapsule-guest/2`, `features` des images système, mise à jour de `capsule-init` et du noyau si nécessaire. | Tests KVM : une image partagée par 3 VM (même inode, `LOCK_SH`) ; montage `ro,noexec` vérifié depuis le harness ; UUID inattendu refusé ; ordre correct avec et sans harness de registre ; harness de base 1 inchangé. |
| **5. Agent de construction** | Agent système par organisation, harness `agentcapsule-corpus-builder` (Dagger, signature), protocole `scan`, `convert`, `package`, cache de conversion, disque de sortie, contrôles du worker, lot de revue, annulation, durée maximale. | Construction KVM d’un dépôt de test mêlant Markdown, PDF texte, PDF scanné, PPTX, XLSX, MP3 et MP4 : rapport complet, `INDEX.md` sous le budget, FTS interrogeable. Une reconstruction après modification d’un seul fichier ne retraite que ce fichier. |
| **6. Publication, liaison et cache** | Tables et migrations, API (`corpora`, `corpus-builds`, `corpus-releases`, `source-credentials`, `agents/{id}/corpora`), états, `try`, `publish`, `deprecate`, templates, rollouts, éviction épinglée, vérification mémorisée, quotas, RBAC, audit. | Tests PG des règles transactionnelles (conflit de version, liaison inter-organisations refusée, quota). Test KVM : rollout d’un template vers `finance-l3:4`, puis éviction de la version 3 une fois plus épinglée. |
| **7. CLI et documentation** | Commandes de la section 7, nouveaux états et types pour `operation wait`, drapeaux ajoutés aux listes blanches de `routes.go`, sections de [cli.md](cli.md). Nouvelles pages `docs/corpus.md` et `docs/api/corpora.md`, à créer. Mises à jour de [registry.md](registry.md), [guest/README.md](guest/README.md) et [observability.md](observability.md). | `TestNamedCommandsHavePublishedHTTPContracts`, `TestOperationStates` et `TestPortableCLI` verts. Le scénario de la section 7 passe de bout en bout sur une installation de test. |
| **8. SDK et adaptateur** | Aides du SDK Python (lister les corpus, ouvrir `fts.sqlite` en lecture seule, lire `INDEX.md`). Documentation pour les harness adaptés : Pi lit les fichiers avec ses outils, et un petit serveur MCP local `corpus` est exposé en option par `capsule-adapter`. | Pi répond à une question en citant une section et son localisateur, sans réseau, sur 3 agents qui partagent la même image. |
| **9. Enrichisseurs** | Déclaration et autorisation des enrichisseurs, exécution sur une construction en revue, images d’extension, montage `ext/`. | Un enrichisseur de démonstration produit une extension montée à côté de la base, sans logique métier dans le cœur. |
| **10. Recette** | Section 8 ci-dessous, charge (N VM qui lisent un corpus de plusieurs Go), sécurité (isolation, absence de contenu dans les journaux, sources piégées), mesures de coûts. | Section 8 entièrement verte, lignes COR en `met`. |

**Ordre.** Après le lot 0, les lots 1, 2, 3 et 4 avancent en parallèle. Le lot 5 a besoin de 1, 3 et 4 ; le lot 6 a besoin de 5. Les lots 7 et 8 suivent, le lot 9 vient en dernier.

- **Première démonstration, sans le lot 2** : un dépôt de Markdown et de PDF texte devient un corpus, monté dans 3 agents Pi, qui répondent en citant.
- **Deuxième démonstration (lot 2)** : vidéos et PDF scannés.

Le suivi en direct des constructions utilise le concentrateur SSE du [plan streaming](plan-streaming.md) dès qu’il est disponible. En attendant, on interroge avec `operation wait`.

## 7. Expérience CLI

Le CLI respecte les conventions de [cli.md](cli.md) : commandes « nom verbe », JSON seulement, clés d’idempotence, suivi par `operation wait`, aucune invite interactive. Les commandes `corpus init` et `corpus lint` sont locales, comme `identity`.

```sh
# 0. Préparer le dépôt (local, sans API)
agentcapsule corpus init ./finance-l3          # écrit un agentcapsule-corpus.yaml commenté
agentcapsule corpus lint ./finance-l3          # fichiers retenus/ignorés, types, volumes estimés

# 1. Enregistrer un jeton Git en lecture seule (jamais réaffiché)
agentcapsule source-credential create --name gitlab-ecole --kind gitlab \
  --host gitlab.example.org --secret-file - < gitlab-ecole.token

# 2. Déclarer le corpus
agentcapsule corpus create finance-l3 --git https://gitlab.example.org/ecole/finance-l3 \
  --ref main --path cours --credential gitlab-ecole --idempotency-key finance-l3-create

# 3. Construire, puis suivre
build=$(agentcapsule corpus build finance-l3 --idempotency-key finance-l3-build-7 | jq -er '.data.id')
agentcapsule operation wait --type corpus-build "$build"
agentcapsule corpus-build show "$build"                    # états, compteurs, coûts, SHA
agentcapsule corpus-build files "$build" --status failed   # fichiers en échec et raisons
agentcapsule corpus-build index "$build" --output-file INDEX.md

# 4. Essayer sur un agent de test, puis publier
agentcapsule corpus-build try "$build" --agent "$TEST_AGENT"
agentcapsule corpus-build publish "$build" --version 3 --idempotency-key finance-l3-v3

# 5. Lier à un template et déployer
agentcapsule template publish --file - --idempotency-key support-rev-4 <<'YAML'
name: support
system_image: ubuntu@2            # image système déclarant la fonction corpus.mount
harness: {name: pi-agent, version: 1.2.0}   # release de base agentcapsule-guest/2
resources: {vcpus: 1, memory_mib: 512, data_volume_mib: 256}
capabilities: [llm.invoke]
llm_profile: support-model
corpora:
  - {name: finance-l3, version: 3, mount: finance}
YAML
agentcapsule rollout start "$DEPLOYMENT" --template support@4

# 6. Gérer les versions
agentcapsule corpus versions finance-l3
agentcapsule corpus-release deprecate "$RELEASE_V2"
```

**Codes de sortie de `operation wait --type corpus-build`.** 0 pour `REVIEW` ou `PUBLISHED` ; 5 pour `FAILED`, `CANCELED` ou `EXPIRED` ; 130 en cas d’interruption. Une fois le plan streaming livré, la commande `corpus-build watch` affichera la progression fichier par fichier.

## 8. Recette de sortie

| Exercice | Condition de réussite |
|---|---|
| Construction d’un dépôt GitLab privé mixte (texte, PDF scanné, PPTX, XLSX, audio, vidéo LFS) | `REVIEW` atteint. Rapport sans fichier oublié. Chaque document a sa vue `.md` et son `doc.json` ; les vidéos ont leurs timecodes et leurs images clés. Coûts imputés au bon budget. |
| Même construction relancée sur le même SHA | Même empreinte d’image, aucune nouvelle inférence (cache de conversion) |
| Modification d’un seul fichier et reconstruction | Seul ce fichier est retraité |
| Publication de `finance-l3:3` puis tentative de republier la version 3 avec un autre contenu | `version_conflict` |
| Rollout sur 3 agents | Une seule image sur l’hôte (même inode), `/corpus/finance/` en lecture seule et `noexec` dans chaque VM |
| Un agent d’une autre organisation tente de lier `finance-l3` | Refus, sans fuite d’existence |
| Source piégée (archive bombe, PDF malformé, nom de fichier hostile, objet LFS altéré) | Construction en échec contrôlé ou fichier ignoré, aucun programme lancé sur l’hôte, objet altéré refusé |
| Disque présenté dans un autre ordre (test d’injection) | `capsule-init` refuse le montage : UUID inattendu |
| Pi interroge le corpus | Réponse citant un document et son localisateur, sans réseau |
| Inspection des journaux, métriques et traces | Aucun fragment de contenu ni secret Git |
| Dépréciation puis désépinglage de la version 3 | Image évincée du cache au passage suivant ; jamais avant |

## 9. Hors périmètre

- Corpus partagés entre organisations (D-C8) et distribution multi-hôtes (D-C9) : P2.
- Mise à jour à chaud d’un corpus dans une VM en marche : Firecracker permet de changer le fichier d’un disque après le boot, mais le remontage dans l’invité et la notification au harness restent à concevoir.
- Webhooks de forge pour reconstruire automatiquement à chaque push : P1, après les webhooks sortants et entrants (EXT-007).
- Dépôt de fichiers locaux sans Git : P1, sous forme d’artefact OCI poussé par le CLI et récupéré par `Fetcher`.
- Recherche visuelle sur les images de pages, graphe de connaissances.
- Intégrité dans l’invité par dm-verity (noyau à étendre) et chiffrement des corpus confidentiels (clé remise par l’autorité au boot) : P2.
