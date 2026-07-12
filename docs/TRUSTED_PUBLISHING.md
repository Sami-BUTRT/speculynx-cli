# Publication PyPI par Trusted Publishing

Ce dépôt publie avec GitHub Actions OIDC : aucun token PyPI, secret GitHub de
publication ou fichier `.pypirc` n'est utilisé. Le workflow est
`.github/workflows/publish.yml` et se déclenche manuellement.

## Paramètres du Trusted Publisher TestPyPI

Dans l'interface TestPyPI, enregistrer un Trusted Publisher avec les valeurs
suivantes :

| Champ | Valeur |
| --- | --- |
| Owner GitHub | `Sami-BUTRT` |
| Repository | `speculynx-cli` |
| Workflow filename | `publish.yml` |
| Environment name | `testpypi` |
| Project name | `speculynx` |

Configurer l'environnement GitHub `testpypi` sans secret de publication et,
si des règles de déploiement sont activées, le limiter à la branche `main`.
Le workflow ne peut publier vers TestPyPI que lorsque sa cible est `testpypi`
et que son ref est `refs/heads/main`.

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

Configurer l'environnement GitHub `pypi` sans secret de publication, avec
approbation requise si disponible, et le restreindre aux tags de release. Le
workflow applique en plus une condition stricte : la cible `pypi` n'est
autorisée que depuis `refs/tags/v0.1.4`.

## Ordre de publication

1. Enregistrer le Trusted Publisher TestPyPI ci-dessus.
2. Dans GitHub Actions, lancer **Publish Speculynx** depuis `main` et choisir
   la cible `testpypi`.
3. Attendre le job `Verify TestPyPI installation` : il installe exactement
   `speculynx==0.1.4` depuis TestPyPI, utilise PyPI seulement comme index
   complémentaire des dépendances, puis valide la CLI, le JSON, le seuil CI,
   le refus Swagger et l'absence du faux positif `KEY-EXP-02` sur JWT.
4. Après cette validation, enregistrer le Trusted Publisher PyPI ci-dessus.
5. Créer et pousser le tag annoté `v0.1.4` selon les conventions de release du
   projet. Ne pas créer ce tag avant la validation TestPyPI.
6. Depuis ce tag, lancer **Publish Speculynx** avec la cible `pypi`, puis
   approuver l'environnement `pypi` si ses règles l'exigent.

Une réussite TestPyPI ne déclenche jamais une publication PyPI officielle : ce
sont deux exécutions manuelles distinctes.
