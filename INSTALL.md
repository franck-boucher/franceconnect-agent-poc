Installation du Connecteur Ozwillo ↔ FranceConnect Agent
========================================================

Le Connecteur Ozwillo ↔ FranceConnect Agent est une application autonome écrite en Go et distribuée sous la forme d'un binaire executable unique.

Pré-requis
----------

La seule dépendance nécessaire sur le serveur est `glibc`.

Le Connecteur dépend par contre d'autres services :
 * Un reverse-proxy comme point de terminaison TLS.
   Il doit passer l'entête `Host` telle quelle (pas `X-Forwarded-Host`) et envoyer une entête `X-Forwarded-Proto: https`.
   Il doit également, bien évidemment, rediriger le trafic HTTP vers HTTPS, avec l'entête `Strict-Transport-Security` appropriée.
 * une base de données MongoDB (testé avec MongoDB 2.6)

Construction à partir des sources
---------------------------------

Construire le Connecteur ne nécessite que les outils Go, ainsi que Git.

La commande `go get github.com/ozwillo/franceconnect-agent-poc` est suffisante pour télécharger toutes les dépendances (avec Git) et compiler le binaire dans `$GOPATH/bin` (le chemin exact du binaire peut être obtenu avec `go list -f '{{.Target}}' github.com/ozwillo/franceconnect-agent-poc`).  
Il est possible d'obtenir un binaire plus petit en passant `-ldflags "-s -w"` pour omettre les symboles de débogage (`go get -ldflags "-s -w" …`).

Installation
------------

Un fichier de service systemd d'exemple est fourni (dans `$(go list -f '{{.Dir}}' github.com/ozwillo/franceconnect-agent-poc)/franceconnect-agent-poc.service`) et doit être modifié pour, a minima, configurer les paramètres.

```
Usage of ./franceconnect-agent-poc:
  -client_id string
    	Client ID for FranceConnect Agent (both at Ozwillo and FranceConnect sides)
  -client_secret string
    	Client secret for FranceConnect Agent (both at Ozwillo and FranceConnect sides)
  -fcaRedirectUri string
    	Redirect URI for FranceConnect Agent (default "https://fcagent.integ01.dev-franceconnect.fr/oidc_callback")
  -listen string
    	Address on which to listen (default ":http")
  -mongo-uri string
    	MongoDB dial URI
  -ozwillo string
    	Base URI of the Ozwillo Kernel (default "https://accounts.ozwillo-preprod.eu")
```

Les paramètres `-client_id`, `-client_secret` et `-mongo-uri` peuvent être configurés par des variables d'environnement `OZFCA_CLIENT_ID`, `OZFCA_CLIENT_SECRET` et `OZFCA_MONGO_URI` respectivement, pour éviter de passer des informations sensibles sur la ligne de commande.  
Par défaut, si `-mongo-uri` (ou `OZFCA_MONGO_URI`) est vide ou omis, le Connecteur cherchera à se connecter à la base de données par défaut sur la machine locale sur le port par défaut de MongoDB, sans authentification ; c'est donc l'équivalent de `mongodb://localhost:27017/`. Le format exact du paramètre est similaire au format standard de MongoDB mais plus libéral : https://godoc.org/gopkg.in/mgo.v2#Dial

Schéma MongoDB
--------------

Le Connecteur utilise 2 collections MongoDB.

La première, `state`, est à usage interne pour conserver l'état entre les différents échanges ; les données sont nettoyées automatiquement par MongoDB grâce à une TTL (l'index est créé automatiquement au lancement du Connecteur).

La second collection, `attributs`, contient les attributs du profil spécifiques à FranceConnect Agent. Les données doivent être insérées manuellement.
Chaque document correspond à un utilisateur Ozwillo, l'`_id` du document correspondant au `sub` de l'utilisateur. Les propriétés `birthplace` et `birthcountry` sont copiées comme propriétés du _User Info_, tandis que les autres propriétés sont encodés comme _Aggregate Claims_ (uniquement celles demandées _via_ `acr_values`).

Par exemple:
```json
{
  "_id": "7d444840-9dc0-11d1-b245-5ffdce74fad2",
  "birthplace": "486",
  "birthcountry": "33",
  "job": "Elu",
  "position": "Maire",
  "belonging_population": "Mairie"
}
