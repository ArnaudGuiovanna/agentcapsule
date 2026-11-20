# Plan d’implémentation du streaming natif AgentCapsule

**Objectif.** Le texte produit par un agent s’affiche chez le client au fil de la génération. Aujourd’hui il arrive d’un bloc, une fois la génération terminée, et le client doit interroger l’API pour le récupérer. Le flux part du fournisseur LLM, traverse la passerelle et le harness, puis la plateforme jusqu’au client. Aucune garantie existante n’est affaiblie : une seule issue par invocation, résultat privé au demandeur, aucun contenu dans les journaux, rejeu après restauration.

**Périmètre.** Ce chantier solde trois éléments de la feuille de route : LLM-02 (« Streaming from the provider »), EVT-01 (« `/events` stream ») et la partie « Events » de CAP-01. Il fait passer EXT-005 (SSE, aujourd’hui en P1, [product.md §5](product.md#5-out-of-scope-for-p0)) dans les exigences P0. Le temps réel audio et vidéo (EXT-006) reste hors périmètre.

Les routes, trames et commandes ci-dessous sont des propositions de conception. Les décisions marquées **D-S** sont à acter dans l’ADR 022 avant le lot 1.

## Suivi du chantier

**20 novembre 2026 · Non démarré.** Le plan s’appuie sur l’état du dépôt à `321143b` (release `v0.0.1`).

| Lot | État |
|---|---|
| 0. Contrats, ADR 022, modèle Quint | Fait ([ADR 022](adr/022-native-streaming.md)) |
| 1. Passerelle : streaming fournisseur | Fait (branche `streaming-lot1` ; [ADR 022](adr/022-native-streaming.md), changements 17 à 22) |
| 2. Canal plateforme : flux LLM vers l’invité | Non démarré |
| 3. Flux de sortie harness → plateforme | Fait, KVM à exécuter (branche `streaming-lot3` ; `TestProductWorkerCarriesTheOutputStreamAndTheCancellation`, image invitée intégrée requise) |
| 4. API : abonnement SSE | Non démarré |
| 5. SDK Python et capsule-adapter | Non démarré |
| 6. CLI | Non démarré |
| 7. Recette, charge et documentation | Non démarré |

## 1. Parcours à livrer

| Qui | Action | Résultat visible |
|---|---|---|
| Alice, via MonApp | Envoie un message à son agent personnel | Les premiers mots apparaissent moins d’une seconde après le premier token du fournisseur, puis le texte progresse. L’issue finale reste lisible par `/result`, comme aujourd’hui. |
| Alice | Observe une réponse longue qui passe par des étapes (« recherche dans le cours… », « vérification… ») | Des événements d’étape annoncés par le harness s’affichent avant le texte |
| Bob | Tente de s’abonner au flux de l’invocation d’Alice | 404, comme pour le résultat |
| Un administrateur | Retire à Alice son droit `read_content` pendant que le flux est ouvert | Le flux se ferme avec l’événement `revoked` dans le délai de revérification |
| Développeur d’un harness Go ou Python | Appelle le modèle en streaming et relaie le texte vers la plateforme | Une API de flux dans le SDK, des trames typées et des limites documentées |
| Harness adapté (Pi, SDK OpenAI ou Anthropic) | Demande `"stream": true` à l’endpoint modèle de `capsule-adapter` | Il reçoit un vrai flux du fournisseur, et plus une réponse complète rejouée au format SSE |
| Sysadmin | Suit une invocation depuis un terminal | `agentcapsule invocation watch ID` affiche les événements au fil de l’eau |
| Plateforme, après une restauration | Relance une invocation perdue sous le même identifiant | Le client reçoit `reset` puis le flux de la nouvelle tentative |
| Alice | Annule une invocation en cours | Le harness reçoit un signal d’annulation sur son flux et peut arrêter le calcul. Aujourd’hui, l’annulation n’arrive jamais au harness ([ROADMAP](../ROADMAP.md), limites connues). |

## 2. Point de départ : où le flux est bloqué aujourd’hui

Tous les sauts lisent le corps entier, le décodent en JSON puis le réécrivent.

| Saut | Code | Blocage |
|---|---|---|
| Passerelle → fournisseur | `llmgateway.Gateway.once` lit tout le corps (`io.ReadAll`, `internal/llmgateway/gateway.go:301`) ; `forwardFields` refuse `stream` puis supprime `stream` et `stream_options` (`forward.go:109-113`) | Aucun flux n’est jamais demandé au fournisseur. L’usage est lu sur le corps complet (`forwardUsage`). |
| Comptage | `LLMService.Call` → `admit` → `execute` → `settle` (`internal/controlplane/llm_service.go:89-174`) | Le règlement suppose une réponse complète. Une coupure en cours de flux n’a pas de traitement prévu. |
| Hôte → invité | `platformHandler.ServeHTTP` écrit un seul objet JSON (`internal/capsuleprotocol/platform.go:121-380`) ; `ServeAuthenticated` : WriteTimeout 35 s (`control.go:116-157`), étendu à 305 s pour les seules routes LLM (`platform.go:145-151`) | Pas de réponse en trames. |
| Relais dans l’invité | `remotePlatform` décode puis rappelle `PlatformClient` (`platform_local_linux.go:16-51`) ; `callWithTimeout` lit tout (`platform.go:430`) ; serveur local WriteTimeout 20 s (`local_linux.go:67-97`) | Le relais réencadre les messages au lieu de les transmettre en continu. |
| Coût par appel | Nouvelle connexion vsock + TLS (`DisableKeepAlives`, `control.go:300-323`), flock dans `verifiedListener`, lecture SQL de `capability.ForRoute`, et `withAdmission` qui écrit deux fois le registre hôte (`firecracker_admission_linux.go:140-228`) | Un appel par delta est inabordable : il faut un seul appel long par flux. |
| Tour exclusif | `WithPreparedDelivery` garde la barrière pendant toute la livraison (`internal/worker/control_linux.go:85-135`) | Le harness ne peut rien émettre avant d’avoir répondu `working`. |
| Worker → API | PostgreSQL est le seul bus. Aucun LISTEN/NOTIFY, aucun lien direct (`internal/api/server.go:1-2`). Les tables UNLOGGED sont refusées (`store.go:134-143`). | Il n’existe aucun canal pour pousser des deltas vers l’API. |
| API → client | Contexte de 10 s par requête (`server.go:223`) ; WriteTimeout 15 s (`cmd/agentcapsule-api/main.go:254`) ; `statusRecorder` n’implémente pas `Flusher` (`api/telemetry.go:74-93`) | Ni SSE ni réponse longue possibles. |
| CLI | Client HTTP avec `Timeout: 30s`, corps lu en entier (`cmd/agentcapsule/http.go:51,139`) | Pas de lecture incrémentale. |
| capsule-adapter | `ModelEndpoint` rejoue la réponse complète au format SSE (`internal/agentadapter/model.go:33-354`) ; A2A : `SendStreamingMessage` non supporté (`a2a.go:594-604`) | Le streaming n’est qu’une compatibilité de SDK. |
| SDK Python | `LLM_CALL_TIMEOUT = 130.0`, alors que le côté Go accepte 300/310 s (`sdk/python/agentcapsule_harness.py:53-62`) | Incohérence à corriger au passage. |

## 3. Architecture cible

```
fournisseur ──SSE──► passerelle (worker) ──NDJSON──► capsule-init ──NDJSON──► harness
                         [lot 1]            [lot 2]   (relais)                   │
                                                                                 │ un flux long
                                                                                 ▼ par invocation
client ◄──SSE── API ◄──NOTIFY + trames scellées (PostgreSQL)◄── worker ◄──NDJSON── harness
      [lot 4]                     [lot 3]                         [lot 3]
```

**Principes**

1. **Les deltas sont éphémères et ne constituent jamais une issue.** Seule `/v1/invocations/complete` produit le résultat. Elle reste transactionnelle, exactement-une-fois et inchangée. Un client qui n’ouvre jamais le flux obtient le même résultat qu’aujourd’hui.
2. **Un appel long par flux, jamais un appel par delta.** L’admission, la capacité et l’autorisation sont contrôlées une fois à l’ouverture, puis le flux tourne hors du verrou d’admission.
3. **Les événements du fournisseur sont relayés sans traduction.** Pour `/v1/llm/forward`, chaque événement est transmis dans le dialecte d’origine (OpenAI ou Anthropic), sans traduction. C’est la règle actuelle de `forward` (« The body is the agent’s ») appliquée au flux.
4. **Les droits sont ceux du résultat.** S’abonner exige exactement les contrôles de `instructionResultTenant` (`internal/controlplane/tenant_agents.go:882-940`). Ils sont revérifiés pendant toute la durée du flux.
5. **Le contenu n’apparaît ni dans les journaux, ni dans les métriques, ni dans NOTIFY.** Une trame stockée est scellée comme un résultat : AEAD transit, AAD liée à l’opération, à la tentative et au demandeur.
6. **La plateforme ignore la sémantique métier.** Elle transporte du texte et des étapes. Si un harness vérifie une réponse avant de la montrer, c’est à lui de n’émettre que des étapes jusqu’à validation ; la plateforme n’a pas à le savoir.

### 3.1 Passerelle (lot 1)

- **Nouvelles fonctions.** `Gateway.ForwardStream(ctx, route, body, sink)` et `Gateway.CompleteStream`. Elles envoient `stream: true` au fournisseur ; pour OpenAI, elles ajoutent `stream_options.include_usage: true`.
- **Lecture du flux.** Un parseur SSE incrémental, borné par ligne et par événement, appelle `sink(event)` pour chaque événement natif.
- **Usage.** Il vient de l’événement final : `usage` pour OpenAI, `message_start` puis `message_delta` pour Anthropic, cache compris comme aujourd’hui.
- **Reprises et coupures.**
  - Avant le premier octet : les tentatives restent celles d’aujourd’hui (connexion, 429, 5xx).
  - Après le premier octet : **aucune reprise**.
  - Une coupure, un délai d’inactivité dépassé ou un flux sans usage final donne `ErrOutcomeUnknown`, et donc `MarkLLMUnknown`. La réconciliation manuelle existante (`llm_reconcile.go`) s’applique.
  - L’événement final de la passerelle porte toujours `outcome` : `completed` ou `outcome_unknown`.
- **Délais.** Le délai fixe de 140 s par tentative devient :
  - un délai jusqu’au premier octet (60 s, configurable) ;
  - un délai d’inactivité entre événements (60 s) ;
  - un plafond total de 300 s, celui du canal.
- **Limites.** La taille cumulée reste bornée par `MaxResponse` (4 MiB). Au-delà, le flux est coupé et l’issue devient `outcome_unknown`.
- **Disjoncteur et traçage.** Un succès n’est enregistré qu’à la fin du flux ; une coupure compte comme un échec. Le span `llm.call` gagne un attribut fermé `mode=stream` et le code d’issue `stream_cut`.

### 3.2 Canal plateforme : flux LLM vers l’invité (lot 2)

- **Nouvelles routes.**
  - `POST /v1/llm/forward/stream` : même requête que `forward`, mais `stream: true` est obligatoire.
  - `POST /v1/llm/complete/stream` : même requête que `complete`.
- **Réponse.** `application/x-ndjson`, une trame JSON stricte par ligne :

```json
{"seq":1,"type":"event","event":{"...événement natif du fournisseur..."}}
{"seq":2,"type":"event","event":{"..."}}
{"seq":9,"type":"end","outcome":"completed","input_tokens":812,"output_tokens":240,"soft_budget_exceeded":false}
```

  Une erreur avant le premier événement garde la réponse JSON d’erreur actuelle et les codes de `safePlatformCode`. Une erreur après est une trame `{"type":"end","outcome":"outcome_unknown"}`.
- **Côté hôte.** `platformHandler` gagne une branche « flux » :
  - écritures avec `http.NewResponseController(w).Flush()` ;
  - échéance d’écriture repoussée à chaque trame (inactivité 60 s, total 305 s) ;
  - le flux occupe un des 16 créneaux par VM pendant toute sa durée ;
  - la capacité requise est `llm.invoke` (`capability.ForRoute`).
- **Côté invité.**
  - `remotePlatform` gagne une méthode de relais en continu : copie trame par trame, chaque trame validée (JSON strict, 64 KiB au plus) avant d’être réécrite.
  - Le serveur local étend son échéance d’écriture par trame, comme l’hôte.
  - `PlatformClient.ForwardLLMStream` renvoie un itérateur de trames et n’utilise pas `callWithTimeout`.
- **Clé d’idempotence.** Comme aujourd’hui, rejouer la même clé ne relance jamais l’appel au fournisseur. Pendant ou après un flux, la réponse est `outcome_unknown` ou `ErrLLMAlreadyProcessed`, selon l’état de la réservation.

### 3.3 Flux de sortie harness → plateforme (lot 3)

- **Route.** `POST /v1/invocations/stream` sur le canal plateforme, en **duplex intégral** : `http.ResponseController.EnableFullDuplex`, disponible depuis Go 1.21.
- **Corps de la requête.** Le harness y écrit ses trames NDJSON. La première ligne ouvre le flux :

```json
{"type":"open","operation_id":"op_…","attempt":2}
{"seq":1,"type":"delta","text":"La VAN se calcule "}
{"seq":2,"type":"step","step":"retrieval","state":"started","label":"Recherche dans le cours"}
{"seq":3,"type":"delta","text":"en actualisant…"}
{"seq":4,"type":"close"}
```

- **Corps de la réponse.** La plateforme y écrit ses trames de contrôle : `{"type":"ack","seq":N}` par lot accepté, `{"type":"cancel"}` si l’invocation est annulée, `{"type":"closed","reason":"terminal|expired|revoked"}`.
  - C’est le premier moyen offert à un harness d’apprendre une annulation avant de compléter.
- **Conditions d’ouverture**, vérifiées dans la transaction d’ouverture :
  - l’invocation est `working` pour **le boot courant** (`authorizeVM`) ;
  - `attempt` correspond à la tentative en cours ;
  - le harness déclare la capacité `stream.output` dans `harness.yaml`. Elle apparaît dans `GET /v1/agents/{id}/capabilities`, ce qui permet au client de savoir s’il a intérêt à s’abonner.
- **Ordre et fin.**
  - `seq` est strictement croissant. Un trou ou une régression ferme le flux avec `invalid`.
  - Les trames arrivées après l’issue terminale sont refusées (`closed: terminal`).
  - Compléter l’invocation ferme le flux.
- **Coalescence côté worker.** Les deltas sont regroupés par fenêtre (150 ms ou 4 KiB, configurable) avant d’être écrits.
  - Chaque lot devient une ligne d’`invocation_stream_chunks` (migration 0056) : `operation_id`, `attempt`, `first_seq`, `last_seq`, `payload_id`, `created_at`.
  - `payload_id` pointe vers `transit_payloads`, scellé comme un résultat (`Transit.putOwned`), avec les parties agent et demandeur.
  - La table est déclarée dans `durableTables`.
- **Réveil de l’API.** Après chaque commit : `pg_notify('agentcapsule_invocation_stream', '<operation_id>:<attempt>:<last_seq>')`. Uniquement des identifiants opaques, jamais de contenu.
- **Limites.** Au plus 2 MiB et 4 096 trames par tentative. Au-delà : une trame `truncated`, le flux s’arrête, l’issue finale n’est pas touchée.
- **Purge.** Les lots sont supprimés 10 minutes après l’issue terminale, ou à la purge de l’invocation. Le délai sert à un client qui se reconnecte tard. La purge s’ajoute à la boucle de rétention existante du worker.
- **Restauration.** Une relance porte une nouvelle `attempt`. Les lots de l’ancienne tentative sont purgés et le client reçoit `reset`.

### 3.4 API : abonnement SSE (lot 4)

- **Route.** `GET /v1/invocations/{id}/events`, `Accept: text/event-stream`. Alias : `/v1/operations/{id}/events`.
- **Droits.** Scope `agent:content:read`, demandeur égal à l’appelant, affectation `read_content` en cours : les mêmes contrôles que `instructionResultTenant`.
  - Ils sont revérifiés toutes les 10 s, et immédiatement à chaque changement de `organizations.policy_version`.
  - En cas d’échec : `event: revoked`, puis fermeture.
- **Dérogations à lever, uniquement sur cette route :**
  - contexte de 10 s remplacé par `context.WithoutCancel` borné à 15 min ;
  - échéance d’écriture repoussée par `ResponseController`, sur le modèle de `api/attachments.go:69-71` ;
  - `Flush` via `ResponseController`, possible parce que `statusRecorder` expose `Unwrap`.
- **Concentrateur.** Une connexion `pgx.Conn` **dédiée**, hors pool, écoute `LISTEN agentcapsule_invocation_stream` et réveille en mémoire les abonnés concernés.
  - Si le concentrateur perd sa connexion, les abonnés passent en lecture périodique (1 s) jusqu’à reconnexion.
  - Aucun abonné ne tient de connexion du pool en continu : chaque lecture de lots est une requête courte.
- **Événements :**

```
event: state      data: {"state":"working","attempt":1}
event: delta      data: {"seq":12,"text":"…"}            id: 1:12
event: step       data: {"seq":13,"step":"retrieval","state":"done"}
event: reset      data: {"attempt":2}
event: truncated  data: {"attempt":1}
event: end        data: {"state":"completed","result":{"content":[…]}}
event: revoked    data: {}
: heartbeat (toutes les 15 s)
```

  L’événement `end` embarque le résultat final s’il fait au plus 32 KiB, la limite actuelle des complétions. Cela évite un aller-retour, avec le même droit que pour `/result`. Lire `/result` démarre l’horloge de rétention `transit.delivered`, comme aujourd’hui.
- **Reprise.** `Last-Event-ID: <attempt>:<seq>` rejoue les lots encore retenus. Si l’identifiant est trop ancien : `reset`, puis tous les lots de la tentative courante.
- **Limites.**
  - Au plus 4 abonnés simultanés par invocation et par principal.
  - Un plafond global d’abonnés par processus API (configurable), avec refus 503 `stream_capacity`.
  - Un délai d’inactivité côté client couvert par les battements de cœur.
- **Télémétrie.**
  - La route est exclue de `agentcapsule_api_request_duration_seconds`.
  - Nouvelles métriques : `agentcapsule_api_streams_active`, `agentcapsule_invocation_stream_frames_total{outcome}`, `agentcapsule_invocation_first_delta_seconds` (de `working` au premier delta), `agentcapsule_llm_stream_first_event_seconds`.
- **HTTP/2.** Il est déjà actif sur l’API : plusieurs flux partagent une connexion.

### 3.5 SDK, adaptateur et CLI (lots 5 et 6)

- **SDK Python.**
  - `Platform.forward_llm_stream(...)` et `complete_llm_stream(...)` sont des générateurs de trames.
  - `Harness.output_stream(operation_id, attempt)` est un gestionnaire de contexte qui expose `delta(text)`, `step(...)` et `cancelled`.
  - `LLM_CALL_TIMEOUT` est aligné sur 300 s.
- **capsule-adapter.**
  - `ModelEndpoint` relaie le vrai flux quand le client demande `stream` ; le rejeu complet reste le repli en cas d’erreur avant le premier octet.
  - Mode `command` : la sortie standard est lue au fil de l’eau et envoyée en `delta`.
  - Mode `server` A2A : `SendStreamingMessage` et `SubscribeToTask` sont pris en charge, et les cartes annoncent `streaming: true`.
- **Pi.** C’est le premier harness de démonstration de bout en bout : il utilise déjà le streaming de son SDK.
- **CLI.**
  - `invocation watch ID` lit le flux SSE avec un client dédié : sans `Timeout` global, avec un délai d’inactivité de 45 s.
  - `agent invoke AGENT --file req.json --watch` enchaîne création puis abonnement. Le parseur accepte désormais `--watch` pour ces deux commandes.
  - **Sortie par défaut** : une ligne JSON par événement, `{"version":1,"event":"delta","data":{…}}`, conforme au contrat de script.
  - **Option `--text`** : n’imprime que le texte des deltas. C’est une exception volontaire à la règle « JSON seulement », pour un humain devant son terminal (D-S5).
  - **Codes de sortie** : 0 pour `completed` ; 5 pour `failed`, `expired`, `canceled` ou `revoked` ; 130 en cas d’interruption.

## 4. Décisions à acter (ADR 022)

| ID | Question | Options | Recommandation |
|---|---|---|---|
| D-S1 | Comment les deltas vont du worker à l’API | (a) lots scellés en table + NOTIFY sans contenu ; (b) lien direct worker → API en mTLS ; (c) table seule, lue par sondage | **(a)**. Elle garde PostgreSQL comme seul bus, survit à un redémarrage de l’API (reprise par `Last-Event-ID`), réutilise le scellement transit et les contrôles de résultat, et fonctionne avec plusieurs workers par hôte. (b) ajouterait une topologie et une surface d’attaque ; (c) ajouterait de la latence. |
| D-S2 | Format des trames du canal plateforme | NDJSON ; SSE encapsulé ; trames binaires préfixées par leur longueur | **NDJSON** : cohérent avec le décodage JSON strict du canal et lisible dans les tests |
| D-S3 | Un flux de sortie au lieu d’appels par lot | Un flux duplex long ; des POST groupés toutes les 250 ms | **Le flux duplex.** Un POST coûte une poignée de main TLS, un flock, une lecture SQL et deux écritures du registre hôte. Le duplex apporte aussi l’annulation. |
| D-S4 | Rétention des lots | Purge à l’issue ; à l’issue + 10 min ; avec le résultat | **Issue + 10 min**, configurable. Les lots restent scellés et sont inclus dans les sauvegardes PostgreSQL le temps de leur courte vie. |
| D-S5 | Sortie humaine du CLI | JSON seulement ; option `--text` | **`--text`** sur `watch` uniquement, documentée comme exception |
| D-S6 | Taille du texte final | Inchangée (32 KiB) ; relevée | **Inchangée dans ce chantier.** Un flux peut dépasser 32 KiB, mais l’issue reste bornée. Les résultats sous forme de fichier (EVT-04) feront l’objet d’un chantier distinct. |

## 5. Lots, dépendances et critères de sortie

| Lot | Travaux | Critère de sortie |
|---|---|---|
| **0. Contrats et modèle** | ADR 022 (D-S1 à D-S6). Brouillons OpenAPI des routes API et des routes du canal. Faire passer EXT-005 dans [product.md §4](product.md) (« Content, capabilities and clients ») et ajouter LLM-009 (streaming fournisseur), avec leurs lignes dans [acceptance.md](acceptance.md). Étendre `spec/invocation_completion.qnt` avec les actions `openStream`, `appendDelta`, `resetAttempt`, `closeStream` et les invariants `noDeltaAfterOutcome`, `deltaMatchesCurrentAttempt`, `deltasNeverAnOutcome`. Les invariants actuels (`atMostOneOutcome`, `resultIffCompleted`, `noLateOrStaleCompletion`) restent valides. Déclarer les nouvelles exécutions dans `spec/projections.md`. | Typecheck et invariants Quint verts. `check-acceptance.py` et la validation OpenAPI passent avec les nouvelles lignes en `not met`. |
| **1. Passerelle** | `ForwardStream` et `CompleteStream` (OpenAI et Anthropic), parseur SSE borné, usage final, disjoncteur, `outcome_unknown` après le premier octet, délais de premier octet, d’inactivité et total. Faux fournisseurs de test : flux nominal, coupure au milieu, absence d’usage, flux trop gros, 429 avant flux. Qualification sur Ollama, qui sert les deux API. | Tests unitaires et PG : une coupure laisse la réservation `unknown` et réconciliable ; le flux nominal règle l’usage exact ; la même clé ne relance jamais l’appel. Exécution réelle sur Ollama. |
| **2. Canal plateforme** | Routes `/v1/llm/*/stream` côté hôte et invité, relais en continu dans `remotePlatform`, échéances par trame, créneau tenu, `PlatformClient.ForwardLLMStream`. | Test KVM : un harness de test reçoit le premier événement avant la fin de la génération ; le serveur local et l’hôte tiennent un flux de 290 s ; 17 flux simultanés donnent un 503 `unavailable`. |
| **3. Flux de sortie** | Route duplex `/v1/invocations/stream`, contrôles d’ouverture, capacité `stream.output` (manifeste, catalogue), coalescence, migration 0056, scellement, NOTIFY, purge, trames `cancel`, `reset` après relance. Annuler une invocation signale désormais le harness. | Tests PG : refus hors `working`, mauvais boot ou mauvaise tentative ; aucun lot accepté après l’issue ; lots illisibles par un autre principal ; purge à échéance. Test KVM : l’annulation atteint le harness. |
| **4. API SSE** | Route `/events`, concentrateur LISTEN, droits et revérification, dérogations de délais, `Last-Event-ID`, battements de cœur, plafonds, télémétrie, OpenAPI, matrice RBAC, tests de conventions (`TestOpenAPIDescribesExactlyTheServedRoutes`, `TestAsynchronousRoutesAreListed`, `TestEveryProblemCodeIsDeclared`). | Tests PG : Bob reçoit 404 ; une révocation en cours de flux ferme sous 10 s ; un redémarrage de l’API pendant le flux est rattrapé par `Last-Event-ID` sans perte ni doublon ; l’événement `end` porte le même résultat que `/result`. |
| **5. SDK et adaptateur** | SDK Python (générateurs, gestionnaire de flux de sortie, délai à 300 s), `ModelEndpoint` en vrai flux, mode `command` incrémental, A2A en streaming, harness Pi de démonstration. | Le scénario `verify-adapter.py --pi` montre une sortie progressive de bout en bout, avec flux du fournisseur et SSE client, sur Ollama. Les SDK officiels OpenAI et Anthropic consomment le flux sans modification. |
| **6. CLI** | `invocation watch`, `agent invoke --watch`, `--text`, client de flux dédié, codes de sortie, [cli.md](cli.md) (section « Follow an invocation as it streams »), tests `routes_test.go` et `portable_test.go`. | Le CLI suit un flux de 5 minutes sans coupure, reprend après une coupure réseau grâce à `Last-Event-ID` et renvoie le bon code de sortie pour chaque issue. |
| **7. Recette et documentation** | Charge : N flux simultanés sur le matériel cible, avec mesure de la latence du premier delta et de la charge PostgreSQL due à la coalescence. Sécurité : isolation entre organisations, révocation, absence de contenu dans les journaux, métriques et NOTIFY (inspection). Docs : [adapter.md](adapter.md) (fin du rejeu), [api/llm.md](api/llm.md) (`stream` accepté), [api/agents-assignments.md](api/agents-assignments.md), [guest/capsule-control.md](guest/capsule-control.md), [observability.md](observability.md), ROADMAP (LLM-02, EVT-01, CAP-01). | Section 8 entièrement verte, lignes d’acceptation EXT-005 et LLM-009 en `met`. |

**Ordre.** Après le lot 0, les lots 1 et 3 avancent en parallèle.

- **Première démonstration, sans LLM (lots 3, 4 et 6)** : le harness `capsule-echo` émet des deltas fictifs et `invocation watch` les affiche. Elle valide la moitié plateforme → client sans dépendre d’un fournisseur.
- **Deuxième démonstration (lots 1, 2 et 5)** : Pi relié à Ollama, avec une sortie progressive de bout en bout.

Le chantier « contextes externes » ([plan-corpus.md](plan-corpus.md)) réutilisera le concentrateur du lot 4 pour suivre ses constructions en direct.

## 6. Limites proposées

| Limite | Valeur par défaut | Où |
|---|---|---|
| Délai jusqu’au premier octet du fournisseur | 60 s | passerelle |
| Inactivité entre événements (fournisseur, canal, SSE) | 60 s / 60 s / battement de cœur toutes les 15 s | passerelle, canal, API |
| Durée totale d’un flux LLM | 300 s (inchangée) | canal |
| Taille d’une trame | 64 KiB | canal |
| Volume par tentative de flux de sortie | 2 MiB, 4 096 trames | worker |
| Fenêtre de coalescence | 150 ms ou 4 KiB | worker |
| Rétention des lots après l’issue | 10 min | worker |
| Abonnés par invocation et par principal / par processus API | 4 / configurable | API |
| Revérification des droits pendant un flux | 10 s, et à chaque changement de `policy_version` | API |
| Durée maximale d’un abonnement SSE | 15 min, puis reconnexion par `Last-Event-ID` | API |

## 7. Sécurité, confidentialité et observabilité

- **Isolation.** Un flux ne s’ouvre que pour l’invocation `working` de la VM appelante, à son boot et à sa tentative courants. Personne d’autre que le demandeur titulaire de `read_content` ne peut le lire.
- **Contenu.**
  - Les lots sont scellés comme des résultats et purgés rapidement.
  - NOTIFY ne transporte que des identifiants opaques.
  - Ni la passerelle ni l’API ne journalisent de texte, et les métriques restent sur des vocabulaires fermés ([observability.md](observability.md)).
- **Déni de service.** Plafonds par tentative, par VM (16 créneaux), par abonné et par processus API. Une fenêtre de coalescence protège PostgreSQL. Les tests de charge du lot 7 fixent les valeurs de production.
- **Coûts.** Un flux coupé n’est jamais facturé deux fois : la réservation passe `unknown` et suit la réconciliation existante.

## 8. Recette de sortie

| Exercice | Condition de réussite |
|---|---|
| Alice invoque Pi via l’API avec abonnement SSE | Premier delta affiché moins d’une seconde après le premier événement du fournisseur (mesuré par les métriques du lot 4). Le texte final de `end` est identique à `/result`. |
| Coupure du fournisseur au milieu d’un flux | Le harness reçoit `end` avec `outcome_unknown`. La réservation apparaît dans `llm unresolved`. Aucun double prélèvement. |
| Bob s’abonne à l’invocation d’Alice | 404, sans aucune fuite d’existence |
| Révocation de l’affectation d’Alice pendant un flux | `revoked` sous 10 s, puis plus rien |
| Redémarrage de l’API pendant un flux | Reconnexion du client par `Last-Event-ID`, sans trou ni doublon |
| Restauration d’un agent pendant un flux | `reset`, puis flux de la nouvelle tentative sous le même identifiant d’invocation |
| Annulation par Alice | Le harness reçoit `cancel` ; l’invocation finit `canceled` ; le flux se ferme |
| 100 flux simultanés sur l’hôte de référence | Aucune erreur, latence du premier delta dans la cible, charge PostgreSQL mesurée et documentée |
| Inspection des journaux, métriques, traces et NOTIFY après la recette | Aucun fragment de contenu |
| Harness sans `stream.output` | Comportement inchangé : `/result` et polling fonctionnent comme en `v0.0.1` |

## 9. Hors périmètre

- Audio et vidéo en temps réel (EXT-006), WebSocket, envoi en continu du client vers l’agent.
- Résultats sous forme de fichier et texte final au-delà de 32 KiB (EVT-04).
- Webhooks sortants (EXT-007).
- Plusieurs hôtes : la conception (NOTIFY, lots en table) ne l’empêche pas, mais la topologie multi-hôtes reste en P2 ([product.md](product.md)).
