# Plan d’implémentation du CLI d’administration AgentCapsule

**Partie 1 — CLI et API du PaaS.** Le sysadmin télécharge `agentcapsule` depuis GitHub Releases, installe le PaaS, rattache une application à une organisation et automatise les accès aux agents. Il peut ensuite exploiter, mettre à jour et restaurer cette installation. La recette part d’un serveur vierge et va jusqu’au départ d’un collaborateur.

**Partie 2 — SDK APP.** Le développeur intégrera MonApp à l’API publique au moyen du **SDK APP**. Son langage sera choisi en deuxième partie. La première partie livre le contrat HTTP, les exemples de requêtes et des scénarios exécutables indépendants de tout langage. Le [SDK Python de harness](../sdk/python/README.md) existant sert à écrire le programme exécuté *dans* une microVM.

Les commandes et les nouvelles routes ci-dessous sont des propositions de conception. Les lots indiquent quels composants construire et comment constater leur achèvement.

## Suivi du chantier

**20 novembre 2026 · Partie 1 (CLI et API) estimée à 95 %. Recette finale de développement sous WSL réussie à 100 % (7 étapes sur 7).** La recette porte sur le média Linux signé `v0.1.0-dev.12`, issu de `c9d1e38`. Le SDK APP et les écrans de MonApp relèvent de la partie 2.

| Parcours | État constaté |
|---|---|
| Installation, mise à niveau et restauration | L’installation hors ligne a repris après interruption dans Ubuntu 24.04 sous WSL2/KVM. La mise à niveau de `dev.6` vers `dev.12` a validé les 55 migrations et les deux sauvegardes locales. Après redémarrage de l’instance, les six images correspondaient au média signé. Le CLI a restauré le volume de 128 Mio du starter d’origine, passé de l’incarnation 3 à 4. La restauration a signalé zéro résultat perdu et le même agent a répondu à une nouvelle invocation. [Recette hôte](cli-host.md#development-qualification-on-wsl2) |
| Administration et MonApp | Sur `dev.12`, Alice et Bob se sont connectés via Keycloak. Chacun a retrouvé son agent personnel et l’agent partagé de Support. Bob ne pouvait pas lire le résultat privé d’Alice. Quand Alice a quitté Support, elle a conservé son agent personnel. Après son départ de l’organisation, l’API a refusé ses appels. D’autres essais ont vérifié la persistance des révocations au redémarrage de l’API et la rotation d’une clé LLM dédiée pendant que le profil partagé restait utilisable. [Contrat MonApp](api/applications.md) · [Guide CLI](cli.md) |
| Capacité et redimensionnement | Deux exécutions Firecracker ont validé trois agents provisionnés et le remplacement de la VM maintenue active après sa mise en veille. La seconde a duré 37,65 s. Sur `dev.12`, le CLI a redimensionné un agent hors déploiement de 1 vCPU et 256 Mio à 2 vCPU et 384 Mio. Sa génération 3 a répondu avec le même volume de 128 Mio. [API des déploiements](api/deployments.md#resizing-one-agent) |
| Distribution | Le média serveur Linux amd64 `dev.12` est signé et vérifié. L’index signé du CLI `dev.13` couvre les exécutables Linux amd64 et ARM64 pour les postes d’administration. Sous QEMU, le binaire ARM64 livré a effectué 49 requêtes TLS lors de l’enrôlement et soumis un redimensionnement accepté par l’API. Les sources et modules Go fournis ont reproduit les deux exécutables hors ligne. Le scan des deux inventaires CLI relève zéro alerte. [Média serveur](release.md#signed-linux-development-build-v010-dev12) · [Distribution des CLI](release.md#signed-linux-workstation-cli-v010-dev13) |
| Livraison publique | Le scan du média `dev.12` relève douze alertes bloquantes sur Ubuntu et Keycloak (une critique et onze élevées). La publication de la RC puis de la version stable reste ouverte. [Résultats du scan](release.md#ubuntu-package-archive-19-november-2026) · [Alertes des images](release-image-qualification.md) |

**Validations hors WSL encore ouvertes.** Les copies S3 et SFTP ont été restaurées sur une seule machine physique. Il reste à vérifier une restauration depuis une sauvegarde sur un hôte physiquement distinct, ainsi que l’exécution native du CLI sous macOS et Windows.

**Suivi des invocations après restauration.** Le CLI Linux `dev.13` inclut le correctif `1d0fcf8` de la commande `operation wait --type invocation`. Sous WSL, le test d’intégration amd64 a exercé la restauration dans PostgreSQL 18.6 et interrogé l’API en HTTPS. Pour l’invocation remise en file, le CLI a observé deux fois `lost`, puis `completed` sous le même identifiant. Il a renvoyé le code 0 et permis de lire le nouveau résultat. Pour le demandeur révoqué, la restauration a écarté la relance. Le CLI utilisé par l’auditeur a affiché `requester_revoked` et renvoyé le code 5. [Qualification du CLI](release.md#signed-linux-workstation-cli-v010-dev13)

Le scénario MonApp vérifie aussi le transfert de Support vers Ventes. Après une nouvelle connexion Keycloak, Alice retrouve ses agents personnels et l’agent de Ventes. Bob conserve son accès à Support. Le workflow de release exige un test des six exécutables sur leur système et leur architecture avant signature. Le test natif Linux amd64 a réussi sous WSL avec les CLI signés `dev.12` et `dev.13`. Le binaire Linux ARM64 a été testé sous QEMU. Les résultats natifs des autres plateformes restent à obtenir. [Scénario MonApp](api/applications.md) · [Contrôles du workflow](release.md)

## 1. Parcours à livrer

| Qui | Action | Résultat visible |
|---|---|---|
| Sysadmin plateforme | Installe le PaaS, crée l’organisation Acme et désigne son premier propriétaire | Installation saine, URL HTTPS, organisation prête et accès initial individuel |
| Administrateur Acme | Enregistre MonApp, autorise son service d’identité et configure la règle « un agent personnel par membre, plus l’agent partagé pour l’équipe Support » | Configuration de connexion à remettre au développeur, règle vérifiable par simulation |
| Administrateur Acme | Choisit combien d’agents provisionner depuis un template et combien garder actifs | Le plan affiche la quantité demandée, les ressources requises et les quotas disponibles. Le suivi indique les agents prêts et ceux en attente. |
| Responsable habilité dans MonApp | Invite Alice dans Support | Invitation limitée à Acme, à l’application et à la personne visée |
| Alice | Accepte l’invitation et se connecte à MonApp | Son assistant personnel et celui de Support apparaissent, avec leur disponibilité |
| Alice et le PaaS | Alice invoque un assistant. Le PaaS vérifie ses droits et réveille la microVM si nécessaire | Réponse dans MonApp. Alice retrouve le même agent lors de sa prochaine session |
| Responsable Acme | Déplace Alice dans une autre équipe, puis désactive son accès lors de son départ | Le droit hérité de Support disparaît, puis les nouvelles demandes d’Alice sont refusées. L’administrateur peut vérifier ces effets dans l’audit |

En partie 1, un client HTTP de recette simule le serveur de MonApp, l’invitation et les appels d’Alice et de Bob. Le responsable utilise une identité autorisée et les deux membres ont chacun leur session de test. Ce scénario valide le contrat avant tout écran MonApp ou développement du SDK APP.

## 2. Point de départ et architecture

| Domaine | À réutiliser | À construire en partie 1 |
|---|---|---|
| Exploitation | Utilitaire local de maintenance, préflights, métriques, diagnostics et audit | Binaire portable, contextes, état agrégé horodaté, opérations distantes autorisées et auxiliaire Linux pour les tâches système. [Outil existant](../cmd/agentcapsule-admin/main.go) |
| Relations organisation–membre–agent | Organisations, équipes, comptes techniques, affectations directes et via équipe, résultats privés au demandeur | Enregistrement d’une application, sessions standard, invitations, pools, attribution automatique et synchronisation du départ. [Droits](api/rbac.md) · [Affectations](api/agents-assignments.md) |
| MicroVM | CPU, RAM et volume chiffré configurables à la création, images de harness vérifiées, quotas, réveil et arrêt | Templates versionnés, création par lots, choix d’image système approuvée, suivi d’une campagne. [Provisionnement](../internal/runtime/firecracker_provisioning_linux.go) · [Capacité mesurée](worker.md) |
| LLM et communication | Fournisseurs, secrets chiffrés, alias, droits par agent/équipe, budgets, Directory et demandes entre agents | Profils partagés/dédiés, diagnostic depuis le worker, explication d’une permission ou d’une demande en attente. [LLM](api/llm.md) · [Interopérabilité](interop.md) |
| Distribution | Workflow de brouillon de release, signatures, provenance et inventaire des dépendances | CLI téléchargeable, distribution serveur complète, installation et mise à jour depuis les artefacts publiés. [Release actuelle](release.md) |

Le CLI utiliserait **l’API HTTPS** pour l’administration courante. L’API possède les règles d’accès, le calcul des affectations et l’état des opérations, également utilisables par d’autres clients. Un auxiliaire Linux aux actions définies gère les paquets, fichiers, services et migrations sur l’hôte, localement ou via SSH. Les opérations longues continuent côté serveur ou hôte après fermeture du terminal. Les accès directs à PostgreSQL et aux autorités restent réservés aux composants d’exploitation habilités.

## 3. Lots, dépendances et critères de sortie

| Lot | Travaux | Critère de sortie |
|---|---|---|
| **0. Contrats et recette** | Inventorier les routes existantes et leurs droits. Définir les ressources nouvelles, les états, les erreurs et les identifiants dans OpenAPI. Préparer les scénarios Acme/MonApp/Alice/Bob et une deuxième organisation. | Chaque tâche du sysadmin est reliée à une commande, un acteur, un transport et un contrôle d’acceptation. Les parcours réservés à MonApp sont identifiés. |
| **1. CLI et identité initiale** | Créer le client Go portable, les contextes plateforme et organisation, la compatibilité client/serveur, le stockage des sessions et les commandes de suivi. Enrôlement local initial expirant et à usage unique, puis accès individuels renouvelables et révocables. | Connexion sur installation de test, rotation, révocation et changement de contexte vérifiés. Un opérateur plateforme peut diagnostiquer l’hôte en respectant les frontières de contenu. |
| **2. Distribution et installation** | Produire la distribution signée, l’auxiliaire système, les unités API/worker, les profils d’installation, le journal de reprise et la mise en service des sauvegardes. | Sur serveur vierge, un sysadmin disposant du seul CLI démarre une microVM, obtient une réponse, redémarre le serveur et reprend une installation interrompue. |
| **3. Administration quotidienne** | Couvrir organisations, quotas, membres, équipes, comptes techniques, clés, attributions, révocations, LLM, agents, registre, files, audit, sauvegardes et communications. | Le CLI permet d’importer un harness signé, d’obtenir une génération réelle via le profil d’inférence choisi par le sysadmin, d’accorder puis retirer un droit, de diagnostiquer une demande inter-agent et de produire un diagnostic expurgé. |
| **4. Templates, capacité et pools** | Ajouter les templates et leurs révisions, les personnalisations, le déploiement par lots de taille choisie, la réservation des ressources et l’inventaire des agents libres. Introduire des images système versionnées compatibles avec le worker. | Pour une demande admise de N agents, une campagne interrompue reprend et aboutit à N identités et N volumes distincts. Le rapport distingue agents provisionnés, actifs et en attente de capacité. |
| **5. Applications et collaborateurs** | Enregistrement de MonApp, connexion standard, permissions techniques limitées à son périmètre, invitations, règles, activation, changement d’équipe et départ. Réutiliser le moteur d’affectations. | Le scénario de la section 1 fonctionne par HTTP avec les mêmes contrôles qu’en production, y compris en cas de doubles inscriptions, pool plein et révocation. |
| **6. Mises à jour, restauration et release** | Distinguer mise à jour du CLI, du PaaS et des microVM. Piloter les campagnes, la maintenance et la restauration. Tester les artefacts à distribuer, puis publier CLI et PaaS sur GitHub. | Candidat `v0.1.0-rc.1` installable depuis GitHub Releases. Publication de `v0.1.0` après validation du parcours complet, d’une mise à niveau entre deux builds distribuables et d’une restauration. |

Après le lot 0, le client, la distribution et les contrats d’identité peuvent avancer en parallèle. La première démonstration commune est « télécharger → installer → se connecter → invoquer un agent ». La seconde ajoute MonApp et un agent personnel. L’essai de charge fait ensuite varier la taille du lot et le nombre de VM actives sur le matériel cible. Les formats de version et de migration du lot 6 doivent être définis dès le lot 0 pour servir à l’installateur.

## 4. Installation, exploitation et mises à jour

La première cible serveur proposée est **Ubuntu 24.04 amd64, systemd et KVM, sur un hôte**. Qualifier séparément les binaires CLI pour Linux, macOS et Windows. L’installateur vérifie les prérequis avant les gros téléchargements, annonce les changements et prend en charge PostgreSQL, les autorités, les certificats, le worker, l’API, Directory et SLIM. Il peut utiliser une PKI, un registre ou PostgreSQL fournis par l’opérateur. À la fin, il distingue services démarrés, invocation vérifiée et sauvegarde hors hôte vérifiée.

Publier dans la même release le CLI par système, la distribution serveur et un manifeste signé. Inclure Firecracker/jailer compatibles, noyau, initrd, adaptateur, unités, configurations et un harness de démarrage accessible sans jeton privé. Épingler les dépendances système et images OCI, joindre sources et notices selon la politique de distribution du dépôt, SBOM et preuves de provenance. Documenter la vérification initiale du CLI puis vérifier chaque téléchargement avant activation. Pour le mode hors ligne, tester un bundle incluant aussi les paquets système et images OCI avec les sorties réseau coupées.

Exemples de syntaxe cible du CLI :

```sh
agentcapsule install
agentcapsule status --watch
agentcapsule doctor
agentcapsule --context acme-prod app register monapp --config monapp.yaml
agentcapsule --context acme-prod template publish --file support.yaml
agentcapsule --context acme-prod deployment plan --template support@3 --count <nombre>
agentcapsule --context acme-prod deployment apply --plan <id>
agentcapsule --context acme-prod pool create assistants-personnels --deployment <id>
agentcapsule --context acme-prod assignment-policy plan --file arrivee-support.yaml
agentcapsule --context acme-prod assignment-policy apply --plan <id>
agentcapsule --context acme-prod access explain --member alice --agent support
agentcapsule update check
agentcapsule update plan --to <version>
agentcapsule update apply --plan <id>
agentcapsule self update
```

Pour les scripts, prévoir configuration déclarative, `--non-interactive`, sortie JSON versionnée, erreurs et codes de sortie documentés. Les mutations sensibles affichent le contexte et la cible. Les secrets passent par trousseau, fichier privé ou entrée standard. Les opérations renvoient un identifiant utilisable avec `operation show` ou `operation wait`. La sortie précise l’effet réel, notamment accès révoqué sur le primaire et confirmation de sa réplication sur le secours.

| Tâche d’exploitation | Comportement attendu |
|---|---|
| Comprendre une panne | `status`, `doctor`, métriques, alertes, journaux filtrés et archive de support présentent le composant affecté, l’ancienneté de la mesure et la prochaine vérification. |
| Gérer les fournisseurs LLM | Le sysadmin choisit l’URL de l’endpoint, le protocole compatible, le modèle et le mode d’authentification. Il peut connecter, par exemple, un serveur Ollama, un serveur vLLM ou une API distante avec sa clé. Le profil peut être commun à l’organisation ou dédié à un agent, avec rotation des clés, budgets et suivi de l’usage. Un échec du profil dédié est signalé sans repli implicite sur la clé commune. |
| Diagnostiquer les échanges | Distinguer annuaire, autorisation, consentement, livraison et réponse. La politique se configure dans le control plane et s’applique à l’entrée du PaaS et dans les passerelles du worker. Les invités conservent le canal vsock authentifié sans accès réseau client direct. |
| Mettre à jour le PaaS | Vérifier la sauvegarde, préparer les artefacts, suspendre les admissions, attendre les travaux, migrer dans l’ordre compatible puis tester une invocation. Le schéma actuellement vérifié à l’identique impose une fenêtre de maintenance. [Migrations](../internal/controlplane/migrations.go) |
| Mettre à jour les microVM | Séparer version applicative, image système et données. Précharger chaque digest par hôte, tester un petit groupe, puis procéder par vagues avec plafond d’indisponibilité, pause sur erreur et reprise. Exposer versions demandée et démarrée. Un agent arrêté peut attendre son prochain réveil. Un état de maintenance durable doit empêcher un réveil inattendu pendant l’opération. [Changement de harness existant](../internal/controlplane/agent_release.go) |
| Revenir à une version ou restaurer | Tester le retour binaire si le format des données et les protocoles le permettent. Sinon, présenter la restauration et la perte de données éventuelle. Préserver clés détruites, révocations et exclusivité du volume à travers la reprise. [Reprise existante](recovery.md) |

La passerelle prend actuellement en charge les protocoles OpenAI-compatible (Chat Completions) et Anthropic (Messages). Pour un endpoint qui accepte les appels sans clé, prévoir un mode d’authentification explicite dans le CLI et l’API, car la validation actuelle exige un secret. Les règles réseau du worker restent applicables à chaque endpoint. [Passerelle LLM](api/llm.md) · [Validation du fournisseur](../internal/controlplane/llm_providers.go)

## 5. Provisionner un nombre d’agents choisi par le sysadmin et les attribuer

Un **template** associe CPU, RAM, volume, image système approuvée, harness, profil LLM et capacités. L’opérateur publie les bases système compatibles. Une organisation crée ses propres templates et peut personnaliser un agent dans ses quotas. Une nouvelle révision s’applique aux agents existants par une campagne explicite. Les limites actuellement acceptées à la création sont 1–8 vCPU, 128–8 192 MiB de RAM et 64–32 768 MiB de disque de données. Pour modifier un agent existant, prévoir CPU/RAM au prochain arrêt contrôlé et une procédure distincte pour agrandir le volume, vérifier son système de fichiers et tester sa restauration.

Le **déploiement** prend la quantité demandée avec `--count`. Le sysadmin peut saisir, par exemple, 50, 100 ou 1 000 agents. Le plan vérifie les quotas d’agents et de stockage de l’organisation ainsi que la capacité de l’hôte. Si la quantité dépasse une limite, il indique la ressource concernée, la quantité requise et la quantité disponible. Une fois la demande admise, le serveur fige la révision, réserve les ressources et provisionne les agents par vagues adaptées à l’hôte. La taille d’une vague peut évoluer indépendamment du nombre total demandé.

Le **pool** regroupe les agents attribuables par une règle donnée. Le dimensionnement compte le stockage de tous les agents et, séparément, les ressources des VM actives et la marge mémoire du VMM. Ajouter les ressources du moteur d’inférence s’il tourne sur le même hôte. Même avec démarrage automatique désactivé, l’initialisation actuelle du volume nécessite un démarrage restreint. Limiter ces démarrages pour protéger les agents qui travaillent déjà. Mesurer sur serveur cible délai d’attribution, délai jusqu’à la première réponse, débit, pression disque et impact sur les autres agents. Les mesures existantes vont jusqu’à 20 VM de référence au repos. [Mesures KVM](worker.md)

Une **règle d’attribution** appartient à une organisation et précise l’application, les membres éligibles, les pools utilisables, les droits autorisés et le comportement en cas d’épuisement. Exemples à couvrir : un agent exclusif par membre, deux agents personnels de profils différents, un agent partagé par équipe. Simuler la règle avant activation. En cas de capacité épuisée, afficher le motif et appliquer le choix configuré entre attente, refus ou création dans les quotas.

Dans PostgreSQL, identifier chaque attribution par organisation, membre, règle et emplacement prévu dans cette règle. Si la règle prévoit deux assistants, chacun a son emplacement stable. Garantir également qu’un agent personnel ne peut être réservé que par une seule personne. Réserver et enregistrer l’affectation dans une transaction, puis faire réaliser les effets physiques par les opérations durables. Si l’agent doit être créé, l’attribution reste en préparation jusqu’à sa disponibilité. Conserver l’origine de chaque droit afin qu’un changement d’équipe retire les seuls droits qui en dépendent. Lors d’un départ, isoler le volume personnel et appliquer la politique de conservation avant toute réutilisation. La simple révocation conserve la mémoire applicative de l’agent.

## 6. Contrat d’intégration remis au SDK APP

La configuration remise au développeur comprend l’URL HTTPS, l’identifiant public de MonApp, les paramètres de connexion, les URI de retour enregistrées et les références des règles autorisées. Les preuves privées de l’application restent dans son backend. Le CLI doit pouvoir enregistrer, vérifier, renouveler et révoquer cette intégration par environnement et organisation.

**Connexion du membre.** Prévoir un fournisseur d’identité livré avec l’installation pour le parcours autonome et la possibilité de raccorder celui de l’entreprise. Utiliser OpenID Connect avec le flux d’autorisation par code et PKCE. Le jeton d’accès destiné à l’API du PaaS porte les droits demandés pour le membre, dont le PaaS vérifie l’appartenance et les affectations à chaque utilisation. L’identité durable s’appuie sur l’émetteur et le sujet vérifiés. L’e-mail sert à acheminer l’invitation. Le mode Ed25519 déjà déployé garde sa compatibilité pendant la transition. [Identité existante](api/tenant-identity.md) · [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) · [Sécurité OAuth](https://www.rfc-editor.org/rfc/rfc9700.html)

**Provisionnement par MonApp.** Enregistrer séparément une autorisation technique limitée à l’organisation, à l’application, aux règles et aux actions permises. MonApp peut traiter une invitation approuvée et demander l’application d’une règle. Le rôle à attribuer et les agents éligibles sont résolus par le PaaS. Vérifier l’autorité du responsable pour l’invitation, l’identité du destinataire à l’acceptation, l’expiration et l’usage unique. Une intégration de provisionnement ne confère aucun accès au contenu d’Alice.

| Fonction consommée par MonApp | Contrat à livrer au lot 5 |
|---|---|
| Inviter puis activer le collaborateur | Mutations publiques documentées, preuve d’invitation et identité vérifiées, identifiant durable de l’activation. Réessayer la même demande restitue son état et les mêmes attributions. |
| Suivre l’activation | État distinguant préparation, prêt, attente de capacité et échec. Identifiant d’opération, motif exploitable, consigne de reprise et délai conseillé lorsque pertinent. |
| Afficher les agents et les utiliser | Réutiliser `GET /v1/agents`, `POST /v1/agents/{id}/invocations` et `GET /v1/invocations/{id}/result` sous l’identité du membre. Le résultat privé reste accessible au demandeur tant que son droit le permet. |
| Changer d’équipe, désactiver, réconcilier | Mutations idempotentes, source d’autorité définie par intégration, ordre ou version des événements et moyen de relire l’état après une coupure. Une ancienne notification ne réactive pas un collaborateur parti. |

Décrire les schémas, scopes, pagination, statuts HTTP et erreurs structurées dans le contrat versionné. Tester notamment mauvaise audience, mauvais tenant, conflit d’idempotence et ressource invisible. La contrainte d’unicité métier doit survivre à l’expiration des reçus HTTP actuels. Fournir des transactions HTTP de référence et les résultats attendus, utilisables depuis n’importe quel langage. [OpenAPI du dépôt](../openapi/openapi.yaml) · [Tests du contrat](../internal/api/openapi_test.go)

## 7. Recette de sortie de la partie CLI

| Exercice | Condition de réussite |
|---|---|
| Télécharger, installer, redémarrer | Utiliser les artefacts du candidat sur KVM réel, reboot inclus. Une signature invalide est refusée. Une installation interrompue reprend avec les mêmes autorités et identités. |
| Acme prépare MonApp | L’opérateur configure le quota, le propriétaire configure l’intégration, simule la règle et lance la campagne. Les étapes sont reproductibles depuis un terminal puis en automatisation. |
| Utiliser le service d’inférence choisi | Un agent autorisé obtient une réponse du modèle configuré via le worker. Vérifier l’endpoint et le modèle effectivement utilisés, l’application du budget et le refus pour un agent sans droit sur ce profil. Le même scénario s’exécute avec les paramètres du fournisseur choisi. |
| Faire varier la quantité demandée | Tester un agent, plusieurs tailles de lot, une demande au quota et une demande au-delà. Pour chaque lot admis, vérifier le nombre exact d’identités et de volumes après reprise. Pour le dépassement, vérifier le motif et l’absence de réservation partielle. Mesurer séparément les agents provisionnés, les VM actives simultanément et la latence sous charge. Publier le matériel et les tailles effectivement testées. |
| Alice et Bob acceptent en même temps | Deux agents personnels distincts, un agent Support partagé si les deux y ont droit. Un double clic, une perte de réponse ou un redémarrage conserve l’attribution initiale. Un pool plein suit sa politique. |
| Vérifier l’isolation | Bob ne peut pas lire le résultat privé d’Alice. Un collaborateur d’une autre organisation ne voit pas leurs agents. Une invitation expirée, une application révoquée ou une demande hors du pool autorisé est refusée. |
| Muter puis désactiver Alice | Perte de l’accès partagé issu de l’équipe, conservation des autres droits légitimes, puis refus des nouveaux appels après désactivation, y compris avec un jeton encore valide temporellement. Les travaux déjà admis et la réplication des révocations sont présentés avec leur état réel. |
| Corriger et récupérer | Rotation d’une clé LLM dédiée sans effet sur les voisins, diagnostic d’un échange inter-agent bloqué, campagne de MAJ suspendue sur échec du premier groupe, restauration qui préserve les révocations. |
| Transmettre à la partie 2 | Le CLI, le bundle serveur, le guide sysadmin, le contrat HTTP et ses scénarios de conformité sont versionnés. Le futur **SDK APP** pourra rejouer la recette avec MonApp dans le langage choisi pour cette deuxième partie. |
