# Publication PyPI par Trusted Publishing

Le dépôt publie avec GitHub Actions OIDC : aucun token PyPI, secret GitHub de
publication ou fichier `.pypirc` n'est utilisé. Le workflow
`.github/workflows/publish.yml` se déclenche automatiquement lorsqu'un tag
`v*` est poussé.

## Paramètres du Trusted Publisher PyPI

Dans l'interface PyPI, enregistrer un Trusted Publisher avec les valeurs
suivantes :

| Champ | Valeur |
| --- | --- |
| Owner GitHub | `Sami-BUTRT` |
| Repository | `speculynx-cli` |
| Workflow filename | `publish.yml` |
| Environment name | `pypi` |
| Project name | `speculynx` |

Configurer l'environnement GitHub `pypi` sans secret de publication. Si des
règles de déploiement sont activées, le restreindre aux tags de release et
ajouter l'approbation requise souhaitée.

## Contrôles du workflow

À partir d'un checkout propre du tag, le workflow :

1. installe le package et exécute toute la suite `unittest` ;
2. supprime les anciens artefacts, puis construit le wheel et le sdist ;
3. exécute `twine check` sur les distributions ;
4. installe le wheel construit et lit sa version via les métadonnées du
   package ;
5. exige une correspondance exacte entre le tag `v<version>`, la version de
   `pyproject.toml`, les métadonnées du package et `speculynx --version` ;
6. publie les artefacts sur PyPI avec OIDC.

La permission `id-token: write` est limitée au job de publication. Le
workflow ne contient aucun token PyPI et aucune version de release codée en
dur dans ses commandes de validation.

## Ordre de publication

1. Vérifier que `main` est propre, synchronisée avec `origin/main`, et que la
   version visée n'existe pas déjà sur PyPI.
2. Exécuter localement les tests, le build et `twine check`.
3. Créer un tag annoté correspondant exactement aux métadonnées du package,
   par exemple `v<version>`.
4. Pousser le tag. Ce push déclenche automatiquement **Publish Speculynx**.
5. Surveiller les jobs GitHub Actions et leurs logs jusqu'à la publication.
6. Attendre que la version apparaisse sur l'index public, puis l'installer
   dans un environnement neuf et rejouer les vérifications fonctionnelles.

Si le seul échec est l'absence du Trusted Publisher, conserver le workflow
OIDC et configurer PyPI avec exactement les cinq valeurs du tableau ci-dessus.
