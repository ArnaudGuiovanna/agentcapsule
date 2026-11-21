# Agent Capsule

**Hébergez les agents IA de votre équipe sur votre infrastructure.** Chaque agent dispose de sa propre microVM Firecracker et d’un disque chiffré. Vous choisissez qui peut l’appeler, quels documents il peut lire et combien il peut dépenser auprès des fournisseurs de modèles.

[Guide de prise en main](docs/guide-sysadmin.md) · [Télécharger la dernière release](https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest) · [Licence MIT](LICENSE)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/hero-dark.png">
  <img src="docs/assets/readme/hero-light.png" alt="" width="100%">
</picture>

## Ce que vous pouvez déployer

Imaginez un assistant chargé de répondre aux questions d’astreinte. Vous publiez les procédures de votre équipe depuis un dépôt Git privé, puis vous montez la version relue dans les agents du support. Chacun consulte les mêmes documents en lecture seule. Lorsqu’un membre pose une question, il voit la réponse se construire dans son terminal et peut la retrouver après une coupure.

| Votre besoin | Ce que fournit Agent Capsule |
|---|---|
| Isoler plusieurs équipes | Organisations, rôles, affectations par agent et résultats privés pour le demandeur. |
| Garder le contrôle des coûts | Une passerelle garde les clés des fournisseurs hors des VM et comptabilise les appels, avec des budgets par organisation ou agent. |
| Mettre à jour les connaissances | Un corpus versionné transforme des documents en Markdown et en index interrogeable. Plusieurs VM partagent la même image sur l’hôte. |
| Exploiter les agents au quotidien | Un CLI pour suivre les opérations, consulter les diagnostics, réaliser une mise à jour et vérifier une restauration. |
| Réutiliser un agent existant | Un adaptateur pour les programmes en ligne de commande. Go, JavaScript, Python et d’autres langages peuvent utiliser le protocole du projet. [Intégration des agents](docs/adapter.md) |

## Premier essai

Il vous faut un **serveur de test Ubuntu 24.04 x86-64** avec KVM et systemd. Le CLI s’installe sur votre poste Linux, macOS ou Windows. Le premier essai vérifie qu’une microVM répond à un message avec l’agent de démonstration fourni. Aucune clé de modèle n’est nécessaire.

Sur votre poste, avec un shell POSIX, `curl` et `cosign` 2.4 ou ultérieur installés depuis une source de confiance, téléchargez le CLI signé. Sous Windows, utilisez Git Bash ou suivez la procédure manuelle. [Installation par système](docs/release.md#verify-a-release)

```sh
curl -fsSLo install-agentcapsule.sh https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh
sh install-agentcapsule.sh --require-signature --dir "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
agentcapsule version
```

Remplacez l’adresse ci-dessous par votre compte SSH et le nom du serveur. Ce compte doit pouvoir utiliser `sudo -n`. Cette commande prépare le plan et retourne son identifiant.

```sh
agentcapsule install --ssh admin@serveur.example.org --plan-only
```

**[Installer le serveur et vérifier la première réponse →](docs/guide-sysadmin.md#installer)**

## Pour aller plus loin

- **Administrer** une organisation, attribuer des droits et suivre les invocations. [Guide du CLI](docs/cli.md)
- **Publier des connaissances** et les monter dans des agents. [Guide des corpus](docs/corpus.md)
- **Brancher une application** ou un agent dans le langage de votre choix. [API HTTP](docs/api/README.md) · [Exemples de harness](examples/)
- **Contribuer** au code, exécuter les tests ou signaler un problème de sécurité. [Contribution](CONTRIBUTING.md) · [Sécurité](SECURITY.md)

**Maturité.** Les parcours de streaming, de conversion et de partage des corpus ont été qualifiés sous PostgreSQL 18.6 et KVM sur une machine de développement. La qualification sur serveur de production et la restauration entre deux machines physiques restent à réaliser. Commencez par un hôte de test. [Matrice de validation](docs/acceptance.md) · [Feuille de route](ROADMAP.md)
