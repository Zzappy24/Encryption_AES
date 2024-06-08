# I. Installer les dépendances
`pip install -r requirements.txt`

# II. Exécuter les tests

## A. Exécuter fonction par fonction
On sépare les étapes pour un fonctionnement plus réaliste.

Dans l'ordre, nous allons :

### 1. Générer une clé
`python generate_key_main.py`
Cela va créer une clé dans le fichier `./keyGenerated/key.json`.

### 2. Chiffrer un message
On récupère la clé dans le fichier `./encryptMessage/message.json`, par exemple : `python encrypt_main.py ce98a434d6ed076114880459b48b9a7630dcc847e87091d00d54ffa87f25213a`
Cela va chiffrer le message défini dans le code en y ajoutant deux autres paramètres de sécurité, à sauvegarder avec le message.

### 3. Déchiffrer un message
Avec la même clé, on déchiffre le message (msg + 2 arguments de sécurité) : `python decrypt_main.py ce98a434d6ed076114880459b48b9a7630dcc847e87091d00d54ffa87f25213a`

On obtient le message déchiffré.

## B. Exécuter les tests
`python test.py`
Il s'agit de tests unitaires pour vérifier le fonctionnement de la logique de chiffrement et de déchiffrement avec lecture des données. À chaque fois, on vérifie que le message déchiffré correspond à celui attendu.