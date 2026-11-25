# Installer et exploiter Agent Capsule sur Ubuntu

**Connectez-vous au serveur Ubuntu qui hébergera les agents. Installez le CLI depuis GitHub, puis lancez `agentcapsule install` sur ce même serveur.** Le CLI télécharge et vérifie le lot de la release, installe les services et vérifie la première réponse du harness `starter` dans une microVM.

## Démarrage rapide sur le serveur

Utilisez une machine dédiée **Ubuntu 24.04 x86_64**, avec systemd, les contrôleurs cgroup v2 `cpu`, `memory` et `pids`, du stockage local persistant et un `/dev/kvm` utilisable. Pour un VPS, vérifiez que l’offre expose KVM à l’invité. Le nom DNS du serveur doit se résoudre depuis celui-ci. Le parcours en ligne nécessite l’accès à GitHub. Le script d’installation vérifie la distribution avec `curl`, `openssl` et un `cosign` de confiance en version 2.4 ou ultérieure. Les exemples de ce guide utilisent aussi `jq` pour lire les reçus JSON. [Installer cosign sur un Ubuntu neuf](#cosign) · [Vérifier une release](release.md#verify-a-release)

**1. Installez le CLI sur le serveur.** Depuis sa console ou après vous y être connecté en SSH, ouvrez un shell root avec `sudo -i` si nécessaire. Exécutez les trois étapes dans ce shell. Le répertoire privé conserve les reçus pour les consulter après une déconnexion.

```sh
umask 077
install -d -m 700 /root/agentcapsule-recette
cd /root/agentcapsule-recette
version='v0.1.1'
base="https://github.com/ArnaudGuiovanna/agentcapsule/releases/download/$version"
curl -fsSLo install-agentcapsule.sh "$base/install.sh" &&
  sh install-agentcapsule.sh --version "$version" --dir /usr/local/bin
export PATH="/usr/local/bin:$PATH"
agentcapsule version
```

**2. Installez le PaaS sur ce même serveur et vérifiez l’écho.** Vérifiez que le CLI affiche la version voulue. La commande publiée choisit son propre tag. Le profil par défaut génère le certificat et réserve un agent de recette.

```sh
agentcapsule install > installation.json
operation=$(jq -er '.operation_id' installation.json)
agentcapsule host operation wait "$operation" > recette.json
jq -e '.state == "succeeded" and .invocation_verified == true' recette.json
jq '{url,services_started,probe_agent,probe_invocation,off_host_backup_verified}' recette.json
```

Le premier `jq` doit afficher `true`. Le worker a démarré la microVM et vérifié la réponse du starter. Le deuxième `jq` donne l’URL publique et les identifiants de preuve. Avec le profil d’essai, `off_host_backup_verified` peut rester à `false`. Pour des données réelles, préparez votre profil TLS et vos destinations de sauvegarde **avant l’installation**. [Profil de production](cli-host.md#profile) · [Sauvegardes et restauration](recovery.md)

**3. Ouvrez localement la session de plateforme.** Pour ce premier essai, l’administrateur système est aussi le premier opérateur. Le certificat et le jeton à usage unique de quinze minutes sont sur la machine. Utilisez l’URL fournie par le reçu.

```sh
api=$(jq -er '.url' recette.json)
agentcapsule context add plateforme --url "$api" --kind platform \
  --ca /etc/agentcapsule/api.crt
agentcapsule --context plateforme login \
  --enrollment-file /etc/agentcapsule/first-enrollment.token
agentcapsule --context plateforme session show
agentcapsule --context plateforme doctor
```

Le contexte HTTPS appartient au compte Unix qui vient de le créer. Lorsque le sysadmin et l’opérateur sont deux personnes distinctes, remettez la CA et la preuve privée directement à l’opérateur nommé pour qu’il fasse le premier `login` sous son propre compte. [Délégation de l’administration](#session)

## Sommaire

1. [Comprendre les trois composants](#composants)
2. [Vérifier le serveur et choisir le média](#preparer)
3. [Planifier l’installation et reprendre une phase](#installer)
4. [Choisir le compte de l’opérateur](#session)
5. [Confier une organisation à son propriétaire](#organisation)
6. [Suivre une réponse en direct](#streaming)
7. [Publier les procédures d’une équipe](#corpus)
8. [Surveiller, sauvegarder et mettre à jour](#exploitation)
9. [Trouver la cause d’un échec](#depannage)

<a id="composants"></a>

## 1. Comprendre les trois composants

| Composant | Où il tourne | À quoi il sert |
|---|---|---|
| CLI `agentcapsule` | Sur le serveur dans le parcours ci-dessus, ou sur un poste d’administration | Installe et exploite l’hôte localement en root. Pour les opérations courantes des opérateurs et propriétaires, il utilise des contextes HTTPS. |
| API, PostgreSQL et worker | Sur le serveur Ubuntu | L’API vérifie les droits, PostgreSQL conserve les opérations et le worker démarre les microVM. |
| Harness | Dans la microVM de chaque agent | Ce programme répond aux demandes. Son disque privé chiffré conserve ses données quand il s’endort. |

Un **corpus** est une version publiée de documents montée en lecture seule dans les agents autorisés. Un **contexte CLI** associe un nom local, un environnement et une identité.

<a id="preparer"></a>

## 2. Vérifier le serveur et choisir le média

Sur le serveur lui-même, vérifiez l’architecture, la version d’Ubuntu, le nom DNS et les contrôleurs. Le plan d’installation vérifie ensuite que le noyau répond réellement aux appels KVM.

```sh
uname -m
. /etc/os-release
echo "$PRETTY_NAME"
hostname -f
test -d /run/systemd/system && test -c /dev/kvm &&
  cat /sys/fs/cgroup/cgroup.controllers
```

<a id="cosign"></a>

**Si cosign manque sur Ubuntu amd64**, récupérez l’exécutable officiel Sigstore depuis le répertoire privé de l’étape 1. Comparez-le à l’empreinte épinglée par le projet avant de l’installer. Sur un Ubuntu minimal, les utilitaires usuels s’obtiennent avec `apt-get update && apt-get install -y ca-certificates curl openssl jq`. Seuls les exemples de lecture JSON de ce guide ont besoin de jq. [Empreinte de référence](../scripts/release-tools.json)

```sh
url='https://github.com/sigstore/cosign/releases/download/v3.1.4'
empreinte='424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa'
curl -fsSLo cosign-linux-amd64 "$url/cosign-linux-amd64" &&
  printf '%s  %s\n' "$empreinte" cosign-linux-amd64 | sha256sum -c - &&
  install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign
/usr/local/bin/cosign version
```

Le profil standard expose l’API en HTTPS sur 9443 et le service d’identité sur 9444. Vérifiez les certificats et la résolution des noms depuis le serveur et les clients. Le lot signé fournit les dépendances du serveur. Si celui-ci est hors ligne, transférez les sept médias vérifiés du tag sur l’hôte et ajoutez `--offline /srv/agentcapsule-release` au plan et à l’installation. Le CLI vérifié peut lui aussi être transféré depuis un poste connecté. [Installation hors ligne](cli-host.md#verify-and-load-offline-assets)

<a id="installer"></a>

## 3. Planifier l’installation et reprendre une phase

Le démarrage rapide utilise le profil par défaut. Pour une **nouvelle** installation avec DNS, PKI ou sauvegardes personnalisés, créez le profil JSON sur le serveur. En root, depuis le répertoire privé, lisez d’abord le résultat du plan. Le champ `state` doit valoir `planned` et `operation_id` doit commencer par `host_`.

```sh
profil=/root/plateforme.json
agentcapsule install --to "$version" --profile "$profil" --plan-only
agentcapsule install --to "$version" --profile "$profil" > installation.json
operation=$(jq -er '.operation_id' installation.json)
agentcapsule host operation wait "$operation" > recette.json
jq . recette.json
```

Après une coupure de terminal, reconnectez-vous au serveur, revenez dans `/root/agentcapsule-recette`, relisez `operation` dans `installation.json` et reprenez `host operation wait`. Pour un état `failed`, utilisez `agentcapsule host operation show "$operation"` puis `journalctl -u "agentcapsule-host@$operation"` sur l’hôte. Après correction de la cause, relancez `agentcapsule host operation resume "$operation"` et attendez le résultat avec le même ID.

**Variante depuis un poste distant.** Installez le CLI sur le poste. Vérifiez la clé SSH du serveur et configurez un compte autorisé à utiliser `sudo -n` sur la cible. Dans ces commandes d’hôte, ajoutez `--ssh admin@agents.example.org` aussi bien à `install` qu’à `host operation wait`. Les chemins du profil et des médias hors ligne restent ceux du serveur. [Administration distante](cli-host.md)

<a id="session"></a>

## 4. Choisir le compte de l’opérateur

Les changements d’hôte nécessitent root. Les commandes de plateforme et d’organisation passent par HTTPS et utilisent l’identité de leur contexte. Pour une exploitation nominative, remettez le fichier d’enrôlement au destinataire par un canal privé, sur le serveur ou sur son propre poste. Avec votre PKI, remettez-lui sa CA de confiance. Il crée lui-même son contexte avec cette CA puis présente la preuve depuis son compte.

```sh
agentcapsule context add plateforme --url "$api" --kind platform --ca api-ca.pem
agentcapsule --context plateforme login --enrollment-file enrolement.token
agentcapsule --context plateforme session show
```

Une preuve est utilisable une fois. Si la première a déjà été consommée dans le parcours de test ou a expiré, l’administrateur habilité émet une nouvelle preuve d’enrôlement. [Enrôler un opérateur](api/organizations.md)


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

| Quand | Commande (root sur l’hôte pour les diagnostics) | Résultat à examiner |
|---|---|---|
| Au début de l’astreinte | `agentcapsule --context plateforme status` | Fraîcheur des données de l’hôte, file de travail et pression disque. |
| Après une installation ou une mise à jour | `agentcapsule host diagnose images` | Identité et état des images de services installées. |
| À chaque contrôle de sauvegarde | `agentcapsule host diagnose backups` | Dernières sauvegardes réussies et état des dépôts. |
| Lors d’une alerte | `agentcapsule host diagnose alerts` | Alertes actives à recouper avec la phase et le journal du service. |

**Avant de confier des données à la plateforme**, configurez une destination hors hôte pour PostgreSQL et pour les volumes chiffrés des agents. Vérifiez les résultats séparément et exercez une restauration de test sur une archive connue. La commande suivante lit l’archive pour contrôler la restauration. Conservez les clés et le matériel de récupération selon la procédure de votre organisation. [Configuration des sauvegardes et restauration](recovery.md)

```sh
agentcapsule restore test --agent agt_EXEMPLE --archive-id arc_EXEMPLE
```

**Pour une mise à jour**, lisez les notes de la release, vérifiez les sauvegardes, choisissez une fenêtre de maintenance puis demandez un plan pour le tag voulu. La plateforme draine les travaux et vérifie la compatibilité des migrations avant la bascule. Une modification du schéma peut rendre un retour binaire impossible. [Mise à jour et conditions de retour arrière](cli-host.md#update-and-recovery)

```sh
agentcapsule update check
agentcapsule update plan --to "$version"
```

Après revue du plan, `agentcapsule update apply --plan IDENTIFIANT_DU_PLAN` lance l’opération. Suivez-la avec `host operation wait` et vérifiez à nouveau `invocation_verified`. La commande `agentcapsule self update` met à jour le binaire CLI sur la machine qui exécute la commande.

<a id="depannage"></a>

## 9. Trouver la cause d’un échec

| Symptôme | Première vérification | Action suivante |
|---|---|---|
| `agentcapsule: command not found` | Lancez `/usr/local/bin/agentcapsule version` sur le serveur. | Si la commande réussit, ajoutez ce répertoire au `PATH` du shell. |
| Le plan s’arrête sur KVM, root ou cgroup | Reprenez les contrôles locaux de l’étape 2 et vérifiez que `id -u` donne 0. | Faites activer la virtualisation sur l’hôte ou corrigez les droits du compte SSH. Relancez le plan. |
| L’opération d’installation passe à `failed` | `agentcapsule host operation show "$operation"` donne la phase en cause. | Sur le serveur, consultez `sudo journalctl -u agentcapsule-host@IDENTIFIANT`. Après correction, reprenez avec `agentcapsule host operation resume "$operation"`. |
| Erreur TLS à la connexion | Comparez le nom dans l’URL au nom DNS du certificat et vérifiez le fichier passé à `--ca`. | Reprenez l’URL fournie par l’installation et la bonne autorité de certification. |
| Accès refusé ou ressource invisible | Dans le contexte de plateforme, consultez `session show`. Dans le contexte d’équipe, consultez `organization current`. | Demandez au propriétaire l’affectation et les permissions correspondant à l’opération. |
| Un fichier manque dans le corpus | Lisez le rapport du build, puis relancez `corpus lint` sur le SHA construit. | Vérifiez les règles du manifeste et, pour les médias, l’alias, les droits et le budget. |
| L’agent répond mais la sauvegarde hors hôte reste à `false` | Vérifiez les destinations dans le profil et `host diagnose backups`. | Configurez les deux filières de sauvegarde et exercez leur restauration avant le passage en service. |

Pour un ticket, conservez la version du CLI, l’identifiant d’opération, la phase et le code d’erreur. Le projet dispose d’un canal privé pour les signalements de sécurité. [Diagnostics et codes de sortie](cli.md#diagnose-and-maintain) · [Signaler un problème de sécurité](../SECURITY.md)
