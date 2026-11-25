# Les commandes du CLI Agent Capsule

Ce guide décrit le binaire `agentcapsule` de **v0.1.1**. Pour installer le PaaS, vous utilisez le CLI **sur le serveur Ubuntu qui hébergera les agents**. Ensuite, le même binaire permet de surveiller l’hôte, puis de gérer les utilisateurs et les agents via l’API. [Manuel complet en PDF](manuel-sysadmin.pdf) · [Installation pas à pas](guide-sysadmin.md)

## Premier démarrage sur le serveur

Dans un shell root sur Ubuntu 24.04 x86-64 avec KVM, systemd et cgroup v2, installez le CLI et lancez la plateforme. La vérification du téléchargement nécessite `curl`, `openssl` et un `cosign` de confiance dans le PATH. La commande `jq` sert uniquement à extraire les champs des reçus dans les exemples. [Préparer les outils](guide-sysadmin.md)

~~~sh
tag=v0.1.1
base="https://github.com/ArnaudGuiovanna/agentcapsule/releases/download/$tag"
curl -fsSLo install-agentcapsule.sh "$base/install.sh" &&
  sh install-agentcapsule.sh --version "$tag" --dir /usr/local/bin
~~~

~~~sh
umask 077
/usr/local/bin/agentcapsule install > installation.json
op=$(jq -er '.operation_id' installation.json)
/usr/local/bin/agentcapsule host operation wait "$op" > recette.json
jq '{state, invocation_verified, off_host_backup_verified, url}' recette.json
~~~

`state: succeeded` et `invocation_verified: true` confirment que l’installation s’est terminée et que la microVM de démonstration a répondu. La sauvegarde hors hôte a son propre résultat. Sans `jq`, lancez simplement `agentcapsule install`, copiez le champ `operation_id`, puis tapez `agentcapsule host operation wait` suivi de cet identifiant.

## Votre première session d’administration

Pour le premier essai, utilisez le certificat local généré et le jeton d’enrôlement créé par l’installateur. Dans un profil avec votre PKI, fournissez l’autorité qui a signé le certificat de l’API. Le jeton initial expire après quinze minutes et sert une fois.

~~~sh
api=$(jq -er '.url' recette.json)
agentcapsule context add plateforme --kind platform --url "$api" \
  --ca /etc/agentcapsule/api.crt
agentcapsule --context plateforme login \
  --enrollment-file /etc/agentcapsule/first-enrollment.token
agentcapsule --context plateforme status
~~~

Pour un premier agent utilisateur, l’opérateur crée une organisation. Son propriétaire ouvre son propre contexte, déploie un agent et lui attribue une permission d’invocation. Le manuel décrit les commandes et les fichiers de ces trois étapes. Voici ensuite une demande entière, depuis le contexte d’organisation du membre affecté. [Créer son premier agent](guide-sysadmin.md)

~~~sh
agentcapsule agent list
agent='agt_REMPLACER_PAR_ID'
cat > demande.json <<'JSON'
{"content":[{"type":"text","text":"Bonjour !"}]}
JSON
agentcapsule agent invoke "$agent" --file demande.json --watch
~~~

## Lire le catalogue

Chaque ligne s’ajoute après `agentcapsule`. Par exemple, la ligne `agent show AGENT` s’utilise avec `agentcapsule agent show agt_…`. Remplacez les mots en majuscules par vos valeurs. Les éléments entre crochets sont facultatifs. `HOST_ID` est un identifiant d’opération d’hôte renvoyé sous `operation_id`. Vous trouverez les identifiants de l’API sous `data`. Utilisez le contexte correspondant.

- **Sur l’hôte**, un shell root suffit pour installer, suivre une opération locale ou vérifier ses sauvegardes.
- **Dans un contexte de plateforme**, l’opérateur contrôle le service, crée les organisations et fixe leurs quotas.
- **Dans un contexte d’organisation**, un propriétaire gère les ressources et les droits. Un membre invoque les agents qui lui sont affectés et accède à ses propres résultats avec la permission de lecture.

`--file` et `--config` lisent un objet JSON ou YAML. `--file -` le lit sur l’entrée standard. Pour une mutation d’API, conservez une clé stable avec `--idempotency-key CLE` si vous devez rejouer la même demande. `--output-file` crée un nouveau fichier privé. Les corps de requête et leurs champs obligatoires sont décrits dans le contrat de l’API. [Schémas et exemples](../openapi/openapi.yaml) · [Matrice des autorisations](api/rbac.md)

### Aller directement à une tâche

- **Exploiter le serveur** — [installer ou mettre à jour](#cli-serveur), [diagnostiquer une panne](#cli-diagnostic), [se connecter et consulter l’état](#cli-session).
- **Ouvrir le service à une équipe** — [créer l’organisation](#cli-organisations), [gérer les personnes](#cli-identites), [déployer un lot](#cli-deploiement), [affecter et interroger un agent](#cli-demandes).
- **Administrer les services associés** — [gérer un agent](#cli-agents), [brancher un modèle](#cli-modeles), [publier des documents](#cli-corpus), [relier une application](#cli-applications), [examiner les échanges](#cli-echanges), [consulter l’audit](#cli-audit).

<a id="cli-outils"></a>

## Aide et outils locaux

Sur la machine qui possède le CLI. Ces commandes s’utilisent avant la connexion à l’API.

| Commande | À quoi elle sert |
|---|---|
| `help` | Affiche l’aide générale et les routes nommées. Pour les options de l’installateur, utilisez `agentcapsule install --help`. |
| `version` | Affiche la version du CLI, la version majeure de l’API et celle du protocole. Accepte aussi `--version`. |
| `self update [--to TAG]` | Remplace le CLI de cette machine par une version vérifiée. Accepte aussi un lot local avec `--offline DOSSIER`. |
| `context add NOM --kind TYPE --url URL` | Enregistre l’adresse HTTPS et le type de compte. TYPE vaut `platform` ou `organization`. Pour une organisation, ajoutez `--organization ORG`. Pour une autorité privée, ajoutez `--ca CA.pem`. |
| `context list` | Liste les connexions configurées sur cette machine. |
| `context show NOM` | Affiche la configuration publique d’une connexion nommée. |
| `context use NOM` | Choisit la connexion à utiliser par défaut dans les commandes suivantes. |
| `identity create --key-file CLE --display-name NOM` | Crée une clé personnelle Ed25519. Avec `--output-file identite.json`, écrit l’identité publique à transmettre à l’opérateur. |
| `identity show --key-file CLE --display-name NOM` | Relit une clé personnelle existante et produit son identité publique. |
| `corpus init DOSSIER` | Crée le manifeste de préparation des documents dans un dépôt local. Options `--title TITRE` et `--language LANGUE`. |
| `corpus lint DOSSIER` | Analyse localement les documents que le manifeste sélectionne et explique les refus. |

<a id="cli-serveur"></a>

## Installer et maintenir le serveur

Sur le serveur Ubuntu, depuis un shell root. L’option commune `--ssh utilisateur@serveur` sert à piloter un autre hôte.

| Commande | À quoi elle sert |
|---|---|
| `install [--plan-only] [--to TAG]` | Installe la plateforme localement. `--plan-only` prépare le plan. `--profile FICHIER` choisit la configuration, `--offline DOSSIER` un lot local. Le reçu contient un `operation_id`. |
| `host operation show HOST_ID` | Affiche immédiatement l’état et la phase d’une opération d’hôte. |
| `host operation wait HOST_ID` | Attend l’issue de l’installation, de la mise à jour ou de la restauration, et imprime le reçu. |
| `host operation resume HOST_ID` | Reprend une opération d’hôte en échec après correction. `--refresh-helper` utilise le helper du CLI actuel pour la reprise. |
| `update check [--to TAG]` | Compare la version installée sur l’hôte et la version disponible ou demandée. |
| `update plan [--to TAG]` | Prépare une mise à jour du serveur et vérifie sa compatibilité. Accepte aussi un profil ou des médias hors ligne. |
| `update apply --plan HOST_ID` | Exécute le plan de mise à jour approuvé. Suivez le reçu avec `host operation wait`. |
| `rollback plan --to TAG` | Vérifie si un retour à la version antérieure indiquée est compatible avec l’installation et le schéma. |
| `rollback apply --plan HOST_ID` | Applique le plan de retour accepté sur le serveur. |
| `archive --agent AGENT --archive-id ARCHIVE` | Capture le volume chiffré de l’agent sous l’identifiant d’archive choisi. |
| `restore test --agent AGENT --archive-id ARCHIVE` | Contrôle l’archive, sa copie et l’accès à la clé. Ce contrôle se fait sans remplacer le volume actif. |
| `restore apply --agent AGENT --archive-id ARCHIVE --restore-id RESTAURATION` | Restaure réellement le volume. Réutilisez le même identifiant pour une reprise. Pour l’agent de démonstration initial, `--verify-starter` contrôle un nouvel écho. |
| `host oidc retire-bootstrap-admin` | Supprime le compte temporaire de Keycloak après la création d’un administrateur permanent. |

<a id="cli-diagnostic"></a>

## Diagnostiquer l’hôte

Depuis le serveur en root, y compris si une panne empêche de se connecter à l’API de la plateforme.

| Commande | À quoi elle sert |
|---|---|
| `host diagnose alerts` | Affiche l’état observé des services systemd et leurs transitions. |
| `host diagnose metrics --service SERVICE` | Lit les métriques locales du service `api`, `worker` ou `authority`. |
| `host diagnose journal --service SERVICE` | Affiche les événements structurés d’un service. Filtres facultatifs `--request-id ID` et `--limit N` (1 à 500). |
| `host diagnose backups` | Donne l’état des dépôts pgBackRest et l’heure de la dernière sauvegarde réussie dans chacun. |
| `host diagnose images` | Compare les images réellement chargées par les services à l’inventaire signé. |
| `host diagnose certificates` | Indique les dates d’expiration, les renouvellements à prévoir et qui les effectue. |
| `host diagnose llm --organization ORG --alias ALIAS` | Teste depuis le worker la configuration d’un alias et de son fournisseur pour l’organisation choisie. |

<a id="cli-session"></a>

## Se connecter et vérifier l’état de la plateforme

Le CLI contacte l’API en HTTPS. Sélectionnez le bon contexte, par exemple avec `--context plateforme` juste après `agentcapsule`.

| Commande | À quoi elle sert |
|---|---|
| `login --enrollment-file JETON` | Ouvre une session d’opérateur de plateforme. Dans un contexte d’organisation, utilisez à la place `login --key-file CLE` ou `login --token-file JETON`. |
| `logout` | Ferme la session de plateforme et efface la connexion locale. Pour un contexte d’organisation, efface l’authentification locale. |
| `session show` | Affiche la session d’opérateur de plateforme actuellement utilisée. |
| `session renew` | Renouvelle la session de plateforme et remplace le jeton précédent. |
| `session revoke SESSION` | Révoque une session de plateforme et les sessions qui en sont issues. |
| `status [--watch]` | En contexte plateforme, affiche l’état opérationnel, la capacité et les files. En contexte d’organisation, vérifie l’API et la session. `--watch` répète l’observation. |
| `doctor` | En contexte plateforme, analyse les observations techniques et indique le composant à examiner. En contexte d’organisation, vérifie la connexion et la session. |
| `support export --output-file ARCHIVE` | Écrit une archive privée. Le contexte plateforme y inclut des diagnostics agrégés. Le contexte d’organisation expose un état de session restreint. |
| `operation show ID [--type TYPE]` | Affiche l’état d’une opération d’API ou de la ressource indiquée. Pour une activation, ajoutez `--app APP`. |
| `operation wait ID [--type TYPE]` | Attend le résultat d’une opération d’API. Les types disponibles sont `deployment`, `harness-import`, `invocation`, `corpus-build`, `rollout`, `volume-growth`, `activation`, `revocation` et `operation`. |
| `api METHODE /v1/CHEMIN [--file FICHIER]` | Appelle directement une route documentée avec le contexte courant. Les méthodes acceptées sont GET, POST, PUT et DELETE. |

<a id="cli-organisations"></a>

## Créer les organisations et fixer leurs limites

Opérateur de plateforme pour la création et les décisions entre organisations. Les commandes portant sur l’organisation courante utilisent un contexte d’organisation autorisé.

| Commande | À quoi elle sert |
|---|---|
| `organization create --name NOM --owner-file IDENTITE` | Crée une organisation et enregistre son premier propriétaire à partir de son identité publique. |
| `organization list` | Liste les organisations de la plateforme et leur état. |
| `organization show ORG` | Consulte une organisation précise depuis la plateforme. |
| `organization disable ORG` | Désactive l’organisation et ferme ses accès. |
| `quota show ORG` | Lit les plafonds et l’usage d’une organisation depuis la plateforme. |
| `quota set ORG --file QUOTAS` | Remplace ses plafonds de ressources. Vérifiez dans le document les agents, VM actives, vCPU, mémoire et stockage. |
| `organization approve-client ORG --file CLIENT` | Approuve le couple émetteur OIDC et identifiant client pour une organisation. |
| `organization clients ORG` | Liste les clients applicatifs approuvés pour cette organisation. |
| `organization withdraw-client ORG APPROBATION` | Retire l’approbation d’un client OIDC. |
| `organization current` | Identifie l’organisation et le membre du contexte connecté. |
| `quota current` | Affiche les limites et la consommation de l’organisation courante selon les droits de l’appelant. |
| `organization capabilities` | Lit la politique autorisant les capacités des agents de l’organisation. |
| `organization set-capabilities --file POLITIQUE` | Remplace la liste des capacités autorisées au niveau de l’organisation. |

<a id="cli-identites"></a>

## Gérer les personnes et les comptes techniques

Propriétaire ou administrateur de l’organisation pour les changements d’identité. Les droits de lecture et le rôle requis dépendent de la commande.

| Commande | À quoi elle sert |
|---|---|
| `member create --file MEMBRE` | Enregistre une personne avec émetteur, sujet, nom affiché et rôle. |
| `member list` | Liste les membres de l’organisation accessibles à l’appelant. |
| `member role MEMBRE --file ROLE` | Remplace le rôle d’un membre actif. |
| `member revoke MEMBRE` | Révoque le membre et ses appartenances aux équipes. |
| `team create --name NOM` | Crée une équipe de l’organisation. |
| `team list` | Liste les équipes. |
| `team show EQUIPE` | Affiche les métadonnées d’une équipe. |
| `team members EQUIPE` | Liste les appartenances à cette équipe. |
| `team add EQUIPE --file MEMBRE` | Ajoute un membre actif. Le fichier contient son `principal_id`. |
| `team remove EQUIPE MEMBRE` | Révoque l’appartenance de cette personne à l’équipe. |
| `team disable EQUIPE` | Désactive l’équipe et révoque ses appartenances. |
| `service-account create --file COMPTE` | Crée un compte technique avec nom et rôle pour un service ou une automatisation. |
| `service-account list` | Liste les comptes techniques de l’organisation. |
| `service-account disable COMPTE` | Désactive le compte technique et révoque ses jetons. |
| `key issue COMPTE --file PORTEE --output-file SECRET` | Émet un jeton de compte technique avec scopes et expiration. Le secret est écrit dans un nouveau fichier privé. |
| `key list COMPTE` | Liste les métadonnées des jetons émis pour ce compte. |
| `key revoke COMPTE JETON_ID` | Révoque le jeton identifié. Utilisez l’identifiant public du jeton. |

<a id="cli-deploiement"></a>

## Préparer les images et déployer un lot

L’opérateur de plateforme approuve les images et importe les harness. L’administrateur d’organisation publie les templates et demande les déploiements selon ses droits.

| Commande | À quoi elle sert |
|---|---|
| `system-image publish --file IMAGE` | Approuve une référence d’image système et les empreintes de son noyau et de son initrd. |
| `system-image list` | Liste les images système approuvées disponibles sur le serveur. |
| `registry import --reference REF_OCI` | Demande l’import d’un harness depuis un registre autorisé. La référence est épinglée par digest. |
| `registry show IMPORT` | Affiche l’état, la progression ou le refus d’un import. |
| `registry list` | Liste les versions de harness disponibles pour le contexte connecté. |
| `registry deprecate VERSION_ID` | Déprécie une version de harness pour les nouveaux usages. |
| `template publish --file TEMPLATE` | Publie une révision immuable précisant l’image système, le harness, les ressources et les capacités. |
| `deployment plan --template NOM@REV --count N [--active-count A]` | Calcule si les ressources permettent de créer N agents dont A actifs. Inspectez `admitted`. |
| `deployment apply --plan PLAN` | Applique un plan après un nouveau contrôle de capacité et lance le provisionnement. |
| `deployment show DEPLOIEMENT` | Affiche la progression du lot et le nombre de VM actives. |
| `pool create NOM --deployment DEPLOIEMENT` | Transforme les agents d’un déploiement appliqué en réserve affectable à une application. |
| `pool show POOL` | Indique l’inventaire et l’état de cette réserve d’agents. |
| `pool expand POOL --count N` | Ajoute des agents au pool à partir de son template et dans les limites de capacité. |
| `rollout start DEPLOIEMENT --template NOM@REV --max-unavailable N` | Lance la transition progressive vers un autre template et limite le nombre d’agents indisponibles. |
| `rollout show ROLLOUT` | Affiche la progression de la mise à jour des agents et l’état du déploiement témoin. |
| `rollout members ROLLOUT` | Liste les agents concernés et leur dernière révision vérifiée. |
| `rollout resume ROLLOUT` | Reprend un déploiement progressif mis en pause après correction. |

<a id="cli-agents"></a>

## Administrer un agent et son disque

Contexte d’organisation avec droits de gestion sur les agents. Un agent conserve son volume privé entre deux démarrages.

| Commande | À quoi elle sert |
|---|---|
| `agent list` | Liste les agents visibles. Copiez un identifiant de la réponse pour les commandes suivantes. |
| `agent show AGENT` | Lit les métadonnées et l’état d’un agent précis. |
| `agent create --file AGENT_JSON` | Crée individuellement un agent et réserve son provisionnement. Indiquez son nom, le harness et les ressources. |
| `agent wake AGENT` | Demande le réveil de la microVM et la reprise avec le volume de l’agent. |
| `agent sleep AGENT` | Demande l’arrêt de la microVM en conservant le volume. |
| `agent idle-policy AGENT --file POLITIQUE` | Règle l’endormissement après inactivité. Le champ `idle_timeout_seconds` à zéro le désactive. |
| `agent release AGENT --file HARNESS` | Associe l’agent à une autre version approuvée de son harness. |
| `agent capabilities AGENT` | Affiche les capacités déclarées et effectivement autorisées pour l’agent. |
| `agent set-capabilities AGENT --file POLITIQUE` | Remplace les capacités que cet agent est autorisé à utiliser. |
| `agent resize AGENT --vcpus N --memory-mib M` | Change les ressources CPU et RAM au cours d’un arrêt contrôlé. Suivez le rollout retourné. |
| `agent grow AGENT --size-mib M` | Agrandit le volume chiffré jusqu’à la taille indiquée en Mio et renvoie une opération à suivre. |
| `volume-growth show OPERATION` | Affiche le stade de l’agrandissement de volume et l’archive associée. |
| `agent delete AGENT` | Supprime un agent déjà activé. Suivez l’opération jusqu’à la révocation de la clé et à la suppression du volume local. Les copies externes suivent leur propre procédure. |

<a id="cli-demandes"></a>

## Donner accès et envoyer une demande

L’administrateur affecte l’agent. Le membre l’invoque avec ses propres droits. Le résultat privé reste lié à l’appelant.

| Commande | À quoi elle sert |
|---|---|
| `assignment grant AGENT --file DROITS` | Affecte l’agent à une personne ou une équipe avec ses permissions, par exemple `invoke` et `read_content`. |
| `assignment list AGENT` | Liste les affectations de cet agent. |
| `assignment replace AGENT AFFECTATION --file DROITS` | Change les permissions d’une affectation pour le même bénéficiaire. |
| `assignment reassign AGENT AFFECTATION --file CIBLE` | Transfère l’affectation à une autre personne ou équipe. |
| `assignment revoke AGENT AFFECTATION` | Révoque l’affectation et l’accès correspondant. |
| `access explain --member MEMBRE --agent AGENT` | Explique les droits effectifs du membre sur l’agent et les équipes ou affectations qui les accordent. |
| `agent invoke AGENT --file DEMANDE [--watch]` | Soumet une demande. Avec `--watch`, suit les événements de la réponse sur la sortie standard. |
| `invocation show INVOCATION` | Affiche l’état et les métadonnées d’une demande déjà créée. |
| `invocation watch INVOCATION [--text]` | Suit une demande existante en direct. `--text` imprime les fragments de texte. |
| `invocation result INVOCATION` | Lit le résultat final pour l’appelant d’origine s’il dispose toujours de `read_content`. |
| `invocation cancel INVOCATION` | Demande l’annulation lorsqu’elle est encore possible pour l’état et l’appelant. |
| `invocation replay INVOCATION` | Remet en file une demande éligible en échec ou expirée avant sa livraison. |
| `queue show` | Affiche la profondeur et les limites des files de demandes de l’organisation. |
| `queue limits --file LIMITES` | Règle les plafonds d’attente par agent et par organisation ainsi que les autres limites prises en charge. |

<a id="cli-modeles"></a>

## Connecter un modèle et suivre son coût

Contexte d’organisation. Les propriétaires et administrateurs gèrent fournisseurs, droits d’appel et budgets. La lecture de la consommation nécessite les droits d’usage.

| Commande | À quoi elle sert |
|---|---|
| `provider create --file FOURNISSEUR [--secret-file CLE]` | Déclare un endpoint de modèles avec son nom, son protocole et son URL. Pour une clé API, choisissez `auth_mode: secret` et fournissez la clé dans le fichier privé. |
| `provider list` | Liste les fournisseurs et leurs métadonnées publiques. |
| `provider rotate FOURNISSEUR --secret-file CLE` | Remplace la clé du fournisseur pour les prochains appels. |
| `provider disable FOURNISSEUR` | Désactive définitivement le fournisseur et ses alias et efface sa clé chiffrée. |
| `alias create --alias NOM --upstream-model MODELE --provider-id FOURNISSEUR` | Nomme le modèle utilisable par les agents. Ajoutez `--file` pour choisir notamment un accès restreint dès la création. |
| `alias list` | Liste les alias de modèles déclarés dans l’organisation. |
| `alias access ALIAS --file ACCES` | Ouvre l’alias à l’organisation ou limite son usage aux agents et équipes autorisés. |
| `alias grant ALIAS --file CIBLE` | Accorde l’usage de l’alias à un agent ou à une équipe. Fournissez exactement un `agent_id` ou un `team_id`. |
| `alias grants ALIAS` | Liste les autorisations de l’alias, y compris celles révoquées. |
| `alias revoke ALIAS AUTORISATION` | Révoque un droit sur l’alias pour les prochaines réservations. |
| `alias prices ALIAS --file TARIFS` | Définit les tarifs utilisés pour estimer le coût des tokens et, selon le modèle, des médias. |
| `alias request-policy ALIAS --file POLITIQUE` | Définit les options et outils du fournisseur autorisés, ainsi que le plafond de sortie. |
| `alias disable ALIAS` | Désactive l’alias pour les prochains appels. |
| `budget create --file BUDGET` | Crée une limite de tokens ou de coût par période et périmètre, avec le mode prévu par l’organisation. |
| `budget list` | Liste les budgets de l’organisation. |
| `budget disable BUDGET` | Désactive un budget pour les réservations futures. |
| `llm usage` | Affiche la consommation, les réservations et les montants d’issue inconnue. |
| `llm unresolved` | Liste les appels dont le règlement reste à rapprocher avec le relevé du fournisseur. |
| `llm settle APPEL --file CONSOMMATION` | Enregistre la consommation confirmée par le fournisseur pour un appel d’issue inconnue. |
| `llm release APPEL` | Libère la réservation après confirmation par le fournisseur que l’appel n’a rien coûté. |

<a id="cli-corpus"></a>

## Publier des documents pour les agents

Contexte d’organisation. L’auteur peut commencer avec les commandes locales `corpus init` et `corpus lint`. Le build distant exige un builder configuré.

| Commande | À quoi elle sert |
|---|---|
| `source-credential create --name NOM --kind FORGE --host HOTE --secret-file CLE` | Enregistre un jeton de lecture GitHub ou GitLab pour récupérer les sources privées. |
| `source-credential list` | Liste les identifiants de forge enregistrés et leurs métadonnées. |
| `source-credential rotate ID --secret-file CLE` | Remplace le secret utilisé lors d’une prochaine récupération Git. |
| `source-credential disable ID` | Désactive définitivement l’identifiant de forge et efface son secret. |
| `corpus create NOM --git URL --ref REF` | Déclare un corpus provenant d’un dépôt Git. Pour une source privée, ajoutez `--credential NOM`. Sur une forge personnalisée, précisez si nécessaire `--kind github` ou `gitlab`. |
| `corpus list` | Liste les corpus de l’organisation. `--name NOM` filtre par nom. |
| `corpus show CORPUS` | Affiche la source et les métadonnées du corpus nommé ou identifié. |
| `corpus build CORPUS [--commit SHA]` | Lance une conversion sur la révision indiquée. Un nom de branche ou de tag peut être fourni avec `--ref` à la place de `--commit`. |
| `corpus versions CORPUS [--include-deprecated]` | Liste les versions publiées de ce corpus. |
| `corpus-build list [--corpus CORPUS]` | Liste les builds et permet de les filtrer avec `--state ETAT`. |
| `corpus-build show BUILD` | Lit l’état du build, le commit retenu, ses compteurs et son coût. |
| `corpus-build watch BUILD` | Suit la conversion en direct, avec les changements de phase et de fichier. |
| `corpus-build cancel BUILD` | Annule un build avant publication et supprime ses contenus temporaires de revue. |
| `corpus-build review BUILD` | Liste les fichiers disponibles pour examiner le résultat de conversion. |
| `corpus-build files BUILD [--status ETAT]` | Lit le rapport des fichiers. Le filtre accepte `converted`, `cached`, `skipped` et `failed`. |
| `corpus-build index BUILD` | Lit l’index Markdown préparé. Avec `--output-file INDEX.md`, le sauvegarde dans un nouveau fichier. |
| `corpus-build try BUILD --agent AGENT [--mount NOM]` | Monte un build en revue sur un agent d’essai à son prochain démarrage. |
| `corpus-build publish BUILD --version N` | Publie une version immuable du corpus après revue. |
| `corpus-release list [--corpus CORPUS]` | Liste les versions publiées. `--include-deprecated` inclut les versions dépréciées. |
| `corpus-release show VERSION_ID` | Décrit une version précise, son image et son état. |
| `corpus-release deprecate VERSION_ID` | Empêche les nouvelles liaisons à cette version. Les montages déjà liés continuent à l’utiliser. |
| `agent corpora AGENT` | Affiche les versions de corpus affectées à cet agent. |
| `agent set-corpora AGENT --file MONTAGES` | Remplace la liste complète des montages de l’agent au prochain démarrage. |

<a id="cli-applications"></a>

## Raccorder une application et ses utilisateurs

L’opérateur approuve d’abord le client OIDC. Le propriétaire de l’organisation configure ensuite l’application. Les activations et invitations sont soumises aux autorisations propres au backend ou à l’administrateur.

| Commande | À quoi elle sert |
|---|---|
| `app register NOM --config CONFIG --output-file SECRET` | Enregistre le client OIDC et écrit son nouveau jeton de provisionnement dans un fichier privé. |
| `app list` | Liste les applications enregistrées de l’organisation. |
| `app show APP` | Lit une inscription applicative, ses paramètres publics et les politiques actives. |
| `app connection APP` | Produit les paramètres de connexion à remettre à l’équipe applicative, y compris issuer, client, API, redirections et politiques. |
| `app verify APP [--issuer-ca CA.pem]` | Vérifie la découverte OIDC et les clés de signature publiées par l’issuer pour l’inscription choisie. |
| `app invite APP --file INVITATION --output-file SECRET` | Crée une invitation pour une adresse, une politique et une échéance. Sa sortie privée contient le jeton d’invitation. |
| `app rotate APP --output-file SECRET` | Remplace le jeton du backend. Transférez le nouveau secret au backend. |
| `app revoke APP` | Désactive l’inscription applicative et ses identifiants de backend. |
| `assignment-policy plan --file POLITIQUE` | Simule le provisionnement et les affectations à partir des pools, équipes et agents, puis retourne l’identifiant du plan. |
| `assignment-policy apply --plan PLAN` | Applique la politique simulée après un nouveau contrôle des pools et équipes. |
| `activation show APP ACTIVATION` | Lit l’état d’un provisionnement applicatif déjà accepté. |
| `activation update APP ACTIVATION --file EVENEMENT` | Applique un événement versionné de changement d’équipe ou de départ pour cette activation. |

<a id="cli-echanges"></a>

## Annuaire et échanges entre agents

Contexte d’organisation avec les droits de gestion ou de lecture sur l’agent. Un échange peut attendre le consentement du destinataire.

| Commande | À quoi elle sert |
|---|---|
| `directory show AGENT` | Lit la description et la visibilité de l’agent dans l’annuaire privé. |
| `directory set AGENT --file FICHE` | Définit les métadonnées de l’agent et sa visibilité dans l’annuaire. |
| `communication inbound AGENT` | Lit les règles de réception des requêtes d’autres agents. |
| `communication configure AGENT --file REGLES` | Modifie la politique de réception et de consentement de l’agent. |
| `communication held AGENT` | Liste les requêtes en attente d’une décision de réception. |
| `communication accept AGENT REQUETE` | Autorise le traitement de la requête en attente. |
| `communication decline AGENT REQUETE` | Refuse la requête en attente. |
| `communication explain AGENT REQUETE` | Diagnostique la visibilité, le consentement, les essais de livraison et le retour de la réponse. |

<a id="cli-audit"></a>

## Audit et révocations

Contexte autorisé pour l’organisation ou pour la révocation consultée. Les filtres de l’API utilisent des identifiants et des dates explicites.

| Commande | À quoi elle sert |
|---|---|
| `audit list [--after CURSEUR] [--limit N]` | Consulte une page d’événements d’audit. Utilisez le curseur pour lire la suivante. |
| `audit export --from DEBUT --to FIN` | Exporte l’audit de l’organisation dans l’intervalle demandé. Fournissez des dates RFC 3339. `--output-file FICHIER` conserve le résultat. |
| `revocation show REVOCATION` | Consulte l’état d’une révocation auprès de l’autorité à partir de son identifiant. |

Les commandes et les options ont été recoupées avec les points d’entrée de cette version. [Routes HTTPS](https://github.com/ArnaudGuiovanna/agentcapsule/blob/v0.1.1/cmd/agentcapsule/routes.go) · [Commandes du serveur](https://github.com/ArnaudGuiovanna/agentcapsule/blob/v0.1.1/internal/hostops/host.py) · [Diagnostics locaux](https://github.com/ArnaudGuiovanna/agentcapsule/blob/v0.1.1/internal/hostops/diagnose.py)
