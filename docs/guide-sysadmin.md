# Exploiter Agent Capsule sur un premier serveur

Ce guide vous accompagne depuis un poste d’administration jusqu’à la première réponse d’un agent sur votre serveur. Le parcours de base utilise le profil de test fourni et l’agent de démonstration `starter`. Vous pourrez ensuite donner la main au responsable d’une équipe, publier ses procédures ou connecter un modèle.

## Sommaire

1. [Comprendre les trois composants](#composants)
2. [Préparer le poste et le serveur](#preparer)
3. [Installer et vérifier la première invocation](#installer)
4. [Ouvrir une session d’administration](#session)
5. [Confier une organisation à son propriétaire](#organisation)
6. [Suivre une réponse en direct](#streaming)
7. [Publier les procédures d’une équipe](#corpus)
8. [Surveiller, sauvegarder et mettre à jour](#exploitation)
9. [Trouver la cause d’un échec](#depannage)

<a id="composants"></a>

## 1. Comprendre les trois composants

| Composant | Où il tourne | À quoi il sert |
|---|---|---|
| Le CLI `agentcapsule` | Votre poste | Installe le serveur par SSH et administre ensuite la plateforme en HTTPS. |
| L’API, PostgreSQL et le worker | Le serveur Ubuntu | L’API vérifie les droits, PostgreSQL conserve les opérations et le worker démarre les microVM. |
| Le harness | Dans la microVM de chaque agent | C’est le programme qui répond aux demandes. Son disque privé chiffré conserve ses données quand il s’endort. |

Un **corpus** est une version publiée de documents, montée en lecture seule dans les agents qui en ont besoin. Un **contexte CLI** est un nom sauvegardé sur votre poste pour choisir le serveur et l’identité à utiliser.

<a id="preparer"></a>

## 2. Préparer le poste et le serveur

Utilisez un serveur de test dédié avec stockage local persistant. Choisissez un nom DNS que votre poste résout et qui correspondra au certificat de l’API. Le profil par défaut utilise le nom complet du serveur pour l’API HTTPS (port 9443) et le service d’identité (port 9444). Le poste a besoin de SSH et d’un accès HTTPS à l’API. Le parcours en ligne télécharge les fichiers signés depuis GitHub. Une procédure distincte permet de transférer les fichiers vers un serveur isolé. [Installation hors ligne](cli-host.md#verify-and-load-offline-assets)

**Sur le poste**, dans un shell POSIX ou Git Bash, remplacez l’adresse de l’exemple. Vérifiez l’identité SSH de la machine selon la procédure de votre équipe. Conservez le même terminal pour les étapes suivantes.

```sh
cible='admin@agents.example.org'
ssh "$cible" 'uname -m; . /etc/os-release; echo "$PRETTY_NAME"; hostname -f'
ssh "$cible" 'test -d /run/systemd/system && test -c /dev/kvm && sudo -n true && cat /sys/fs/cgroup/cgroup.controllers'
```

La première commande doit afficher `x86_64`, Ubuntu 24.04 et le nom DNS attendu. La seconde doit réussir et afficher au moins `cpu`, `memory` et `pids`. Sur une VM hébergée, demandez une instance qui expose KVM à l’invité. Le plan d’installation vérifie ensuite que le noyau répond réellement à l’API KVM.

**Sur le poste**, installez `curl`, `jq` et un `cosign` de confiance (version 2.4 ou ultérieure). `jq` lit les réponses JSON. `cosign` vérifie que GitHub a signé l’index des fichiers pour le workflow et le tag attendus. Le tag ci-dessous fixe la même version pour le client et le serveur. [Installation de cosign](https://docs.sigstore.dev/cosign/system_config/installation/) · [Vérification manuelle pour Windows, macOS et Linux](release.md#verify-a-release)

```sh
version='v0.1.0'
curl -fsSLo install-agentcapsule.sh "https://github.com/ArnaudGuiovanna/agentcapsule/releases/download/$version/install.sh"
sh install-agentcapsule.sh --version "$version" --require-signature --dir "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
agentcapsule version
```

Vérifiez que la sortie indique le tag choisi. Pour un futur terminal, ajoutez le répertoire d’installation au `PATH` de votre shell.

<a id="installer"></a>

## 3. Installer et vérifier la première invocation

Le profil par défaut installe PostgreSQL, le service d’identité Keycloak, les services privés de communication, l’API et le worker. Le certificat de test est généré sur le serveur. Pour utiliser votre propre DNS, vos certificats ou une destination de sauvegarde, préparez le profil JSON **sur le serveur**, puis fournissez le même `--profile /chemin/profil.json` au plan et à l’installation. [Champs du profil](cli-host.md#profile)

**Sur le poste**, demandez le plan et lisez la version et l’état renvoyés avant de lancer l’installation.

```sh
agentcapsule install --ssh "$cible" --to "$version" --plan-only
```

L’état attendu est `planned` et le champ `operation_id` commence par `host_`. Avec les mêmes options, lancez l’installation. Le fichier de réponse permet de retrouver l’identifiant si le terminal ferme.

```sh
agentcapsule install --ssh "$cible" --to "$version" > installation.json
operation=$(jq -er '.operation_id' installation.json)
agentcapsule host operation wait "$operation" --ssh "$cible"
```

| Champ du résultat | Ce que vous avez vérifié |
|---|---|
| `state: succeeded` | L’opération demandée est arrivée à son terme. |
| `services_started: true` | Les services ont démarré. Le champ `url` donne l’adresse HTTPS de l’API. |
| `invocation_verified: true` | Le worker a démarré une vraie microVM, envoyé un message et relu la même réponse. `probe_agent` et `probe_invocation` identifient cet essai. |
| `off_host_backup_verified` | `true` confirme la vérification d’une sauvegarde hors hôte. Avec le profil de test sans destination, cette valeur peut être `false` même si l’agent répond. |

L’installation continue sur le serveur si SSH se coupe. Rouvrez un terminal, redéfinissez `cible`, relisez `operation` depuis le fichier, puis répétez `host operation wait`.

<a id="session"></a>

## 4. Ouvrir une session d’administration

Effectuez cette étape dès la fin de l’installation. Le fichier d’enrôlement du premier opérateur est utilisable une fois et expire après 15 minutes. L’exemple utilise le certificat généré et crée un répertoire privé sur le poste. Si vous fournissez votre propre chaîne TLS, utilisez votre autorité de certification pour `--ca`.

```sh
dossier=$(mktemp -d)
chmod 700 "$dossier"
umask 077
ssh "$cible" 'sudo -n cat /etc/agentcapsule/api.crt' > "$dossier/api.crt"
ssh "$cible" 'sudo -n cat /etc/agentcapsule/first-enrollment.token' > "$dossier/enrolement"
```

Renseignez l’URL exacte obtenue à l’étape 3. Conservez le fichier de l’autorité de certification pour les connexions suivantes. Le jeton reste dans le fichier privé.

```sh
api='https://agents.example.org:9443'
agentcapsule context add plateforme --url "$api" --kind platform --ca "$dossier/api.crt"
agentcapsule --context plateforme login --enrollment-file "$dossier/enrolement"
agentcapsule --context plateforme session show
agentcapsule --context plateforme doctor
```

Le nom du contexte et l’identité retournée par `session show` vous permettent de vérifier sur quelle installation vous travaillez avant une modification.

<a id="organisation"></a>

## 5. Confier une organisation à son propriétaire

L’opérateur crée l’organisation. Son propriétaire gère ensuite les membres, les agents, les modèles et les budgets. Les deux personnes peuvent utiliser des machines différentes.

1. **Sur le poste du propriétaire**, créez l’identité et conservez la clé privée sous son contrôle. Transmettez uniquement le fichier public `proprietaire.json` à l’opérateur.

   ```sh
   umask 077
   agentcapsule identity create --key-file equipe.pem --display-name "Responsable support" --output-file proprietaire.json
   ```

2. **Sur le poste de l’opérateur**, créez l’organisation. La clé d’idempotence permet de rejouer la même commande en cas de perte de la réponse.

   ```sh
   agentcapsule --context plateforme organization create --name Support --owner-file proprietaire.json --idempotency-key creer-support
   ```

3. Transmettez au propriétaire l’identifiant `data.id` de l’organisation, l’URL de l’API et son certificat de confiance. **Sur son poste**, il peut alors créer son contexte. Remplacez les valeurs de l’exemple et utilisez le chemin de son certificat.

   ```sh
   agentcapsule context add support --kind organization --organization org_EXEMPLE --url https://agents.example.org:9443 --ca api.crt
   agentcapsule --context support login --key-file equipe.pem
   ```

Les droits sur le contenu sont attribués par agent. Pour qu’un membre pose une question puis lise la réponse, attribuez-lui les permissions `invoke` et `read_content` sur l’agent visé. [Rôles et affectations](api/agents-assignments.md) · [Configurer les quotas et les équipes](cli.md#enroll-the-platform-operator-and-hand-acme-to-its-owner)

<a id="streaming"></a>

## 6. Suivre une réponse en direct

Utilisez un contexte d’organisation connecté comme membre autorisé et l’identifiant d’un agent qui lui est affecté. Pour recevoir du texte progressivement, le programme de l’agent doit émettre des fragments et avoir la capacité effective `stream.output`. Une invocation du harness de démonstration peut simplement rendre son résultat en une fois.

```sh
agent='agt_EXEMPLE'
printf '%s\n' '{"content":[{"type":"text","text":"Quelle procédure suivre pendant une astreinte ?"}]}' > demande.json
agentcapsule --context support agent invoke "$agent" --file demande.json --watch
```

La sortie contient un objet JSON par événement. Pour suivre à nouveau une invocation déjà créée, récupérez son identifiant et lancez `agentcapsule --context support invocation watch IDENTIFIANT --text`. Le CLI reprend une connexion interrompue. Pour traiter des reprises dans un script, gardez le format JSON afin de reconnaître l’événement `reset`. [Contrat du streaming](cli.md#follow-an-invocation-as-it-streams)

<a id="corpus"></a>

## 7. Publier les procédures d’une équipe

Commencez avec un document Markdown ou un PDF texte dans un dépôt GitHub que vous contrôlez. Dans votre copie locale, `agentcapsule corpus init .` crée le manifeste. `agentcapsule corpus lint .` montre les fichiers retenus ou ignorés. Enregistrez puis poussez le manifeste et le document dans votre dépôt source.

**Une fois par plateforme**, publiez, signez et importez le harness de construction. Configurez le worker pour utiliser son nom et sa version ainsi qu’une image système compatible `corpus.mount`. L’image du builder de référence occupe 1 792 Mio. La lecture de Markdown et de PDF texte fonctionne sans fournisseur de modèles. OCR et transcription nécessitent les alias et les tarifs de l’organisation. [Installation du builder](../examples/corpus-builder/README.md) · [Accès aux modèles et coûts](api/corpora.md#model-access-and-costs)

**Sur le poste du propriétaire**, utilisez un jeton GitHub de lecture limité à votre dépôt, placé dans un fichier privé. Remplacez l’URL par la vôtre.

```sh
agentcapsule --context support source-credential create --name git-support --kind github --host github.com --secret-file github-lecture.token
agentcapsule --context support corpus create procedures --git https://github.com/VOTRE-ORG/VOTRE-DEPOT --ref main --credential git-support --idempotency-key declarer-procedures
build=$(agentcapsule --context support corpus build procedures --idempotency-key construire-procedures-1 | jq -er '.data.id')
agentcapsule --context support corpus-build watch "$build"
agentcapsule --context support corpus-build files "$build" --status failed
agentcapsule --context support corpus-build index "$build"
```

À l’état `REVIEW`, lisez l’index et vérifiez les fichiers en échec. Après validation, publiez avec `agentcapsule --context support corpus-build publish "$build" --version 1 --idempotency-key publier-procedures-1`. Liez cette version à un agent ou à son modèle de déploiement. Au prochain démarrage de l’agent, son harness pourra lire les fichiers et interroger l’index SQLite sous `/corpus/`. [Essai sur un agent et liaison d’une version](cli.md#build-and-publish-a-corpus)

<a id="exploitation"></a>

## 8. Surveiller, sauvegarder et mettre à jour

| Quand | Commande depuis le poste | Résultat à examiner |
|---|---|---|
| Au début de l’astreinte | `agentcapsule --context plateforme status` | Fraîcheur des données de l’hôte, file de travail et pression disque. |
| Après une installation ou une mise à jour | `agentcapsule host diagnose images --ssh "$cible"` | Identité et état des images de services installées. |
| À chaque contrôle de sauvegarde | `agentcapsule host diagnose backups --ssh "$cible"` | Dernières sauvegardes réussies et état des dépôts. |
| Lors d’une alerte | `agentcapsule host diagnose alerts --ssh "$cible"` | Alertes actives à recouper avec la phase et le journal du service. |

**Avant de confier des données à la plateforme**, configurez une destination hors hôte pour PostgreSQL et pour les volumes chiffrés des agents. Vérifiez les résultats séparément et exercez une restauration de test sur une archive connue. La commande suivante lit l’archive pour contrôler la restauration. Conservez les clés et le matériel de récupération selon la procédure de votre organisation. [Configuration des sauvegardes et restauration](recovery.md)

```sh
agentcapsule restore test --agent agt_EXEMPLE --archive-id arc_EXEMPLE --ssh "$cible"
```

**Pour une mise à jour**, lisez les notes de la release, vérifiez les sauvegardes, choisissez une fenêtre de maintenance puis demandez un plan pour le tag voulu. La plateforme draine les travaux et vérifie la compatibilité des migrations avant la bascule. Une modification du schéma peut rendre un retour binaire impossible. [Mise à jour et conditions de retour arrière](cli-host.md#update-and-recovery)

```sh
agentcapsule update check --ssh "$cible"
agentcapsule update plan --to "$version" --ssh "$cible"
```

Après revue du plan, `agentcapsule update apply --plan IDENTIFIANT_DU_PLAN --ssh "$cible"` lance l’opération. Suivez-la avec `host operation wait` et vérifiez à nouveau `invocation_verified`. La commande `agentcapsule self update` met à jour le CLI du poste.

<a id="depannage"></a>

## 9. Trouver la cause d’un échec

| Symptôme | Première vérification | Action suivante |
|---|---|---|
| `agentcapsule: command not found` | Lancez `"$HOME/.local/bin/agentcapsule" version`. | Si la commande réussit, ajoutez ce répertoire au `PATH` du poste. |
| Le plan s’arrête sur KVM, sudo ou cgroup | Reprenez les deux commandes SSH de l’étape 2. | Faites activer la virtualisation sur l’hôte ou corrigez les droits du compte SSH. Relancez le plan. |
| L’opération d’installation passe à `failed` | `agentcapsule host operation show "$operation" --ssh "$cible"` donne la phase en cause. | Sur le serveur, consultez `sudo journalctl -u agentcapsule-host@IDENTIFIANT`. Après correction, reprenez avec `agentcapsule host operation resume "$operation" --ssh "$cible"`. |
| Erreur TLS à la connexion | Comparez le nom dans l’URL au nom DNS du certificat et vérifiez le fichier passé à `--ca`. | Reprenez l’URL fournie par l’installation et la bonne autorité de certification. |
| Accès refusé ou ressource invisible | Dans le contexte de plateforme, consultez `session show`. Dans le contexte d’équipe, consultez `organization current`. | Demandez au propriétaire l’affectation et les permissions correspondant à l’opération. |
| Un fichier manque dans le corpus | Lisez le rapport du build, puis relancez `corpus lint` sur le SHA construit. | Vérifiez les règles du manifeste et, pour les médias, l’alias, les droits et le budget. |
| L’agent répond mais la sauvegarde hors hôte reste à `false` | Vérifiez les destinations dans le profil et `host diagnose backups`. | Configurez les deux filières de sauvegarde et exercez leur restauration avant le passage en service. |

Pour un ticket, conservez la version du CLI, l’identifiant d’opération, la phase et le code d’erreur. Le projet dispose d’un canal privé pour les signalements de sécurité. [Diagnostics et codes de sortie](cli.md#diagnose-and-maintain) · [Signaler un problème de sécurité](../SECURITY.md)
