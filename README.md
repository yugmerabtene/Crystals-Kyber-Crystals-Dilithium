# 🔒 Algorithmes de Chiffrement et de Signature : Symétriques, Asymétriques et Post-Quantiques

## 🔍 1. Introduction
Les algorithmes de chiffrement et de signature sont au cœur de la sécurité des communications modernes. Ils se divisent en deux grandes catégories :
- **Symétriques** (une seule clé pour chiffrer et déchiffrer).
- **Asymétriques** (une paire de clés publique/privée).

## 🔑 2. Algorithmes Symétriques
### 🌐 Algorithmes Populaires :
- **AES (Advanced Encryption Standard)** : Chiffrement par bloc (128, 192, 256 bits).
- **ChaCha20** : Algorithme de flux rapide et efficace.
- **3DES** : Désormais déprécié.

### 📝 Exemple Java (AES-256) :
```java
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESExample {
    public static void main(String[] args) throws Exception {
        String secret = "SuperSecretKey123";
        byte[] key = secret.getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted = cipher.doFinal("Message secret".getBytes());
        System.out.println("Chiffré : " + Base64.getEncoder().encodeToString(encrypted));
    }
}
```

---

## 🛡️ 3. Algorithmes Asymétriques
### 🌐 Algorithmes Populaires :
- **RSA** : Basé sur la factorisation des grands nombres.
- **ECDSA (Elliptic Curve Digital Signature Algorithm)** : Basé sur les courbes elliptiques.
- **Diffie-Hellman** : Utilisé pour l'échange de clés.

### 📝 Exemple Java (RSA) :
```java
import java.security.*;
import java.util.Base64;

public class RSAExample {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = cipher.doFinal("Message secret".getBytes());
        System.out.println("RSA Chiffré : " + Base64.getEncoder().encodeToString(encrypted));
    }
}
```

---

## 🧬 4. Algorithmes Post-Quantiques (PQC)
### 🔐 Algorithmes Populaires :
- **Crystals-Kyber** : Échange de clés.
- **Crystals-Dilithium** : Signature numérique.
- **Falcon** : Signature plus compacte.

---

## 🔐 Crystals-Kyber et Crystals-Dilithium vs RSA et ECDSA

### 🚀 Pourquoi Kyber et Dilithium ?
Les algorithmes comme **RSA** et **ECDSA** sont vulnérables aux attaques des ordinateurs quantiques à cause de l'**algorithme de Shor**.  
**Crystals-Kyber** et **Crystals-Dilithium** sont conçus pour :  
- **Résister aux attaques quantiques.**  
- **Remplacer RSA/ECDSA** dans les échanges de clés et les signatures numériques.  
- **Sécuriser les communications** à long terme.  

---

### 🗊 Comparaison : Kyber, Dilithium, RSA et ECDSA

| **Caractéristique**                | **Crystals-Kyber**               | **Crystals-Dilithium**           | **RSA**                          | **ECDSA**                        |
|-----------------------------------|----------------------------------|---------------------------------|---------------------------------|---------------------------------|
| **Type**                           | Échange de clés (KEM)             | Signature numérique (DSA)        | Échange de clés et signature     | Signature numérique             |
| **Sécurité contre les quantiques** | ✔️                              | ✔️                               | ❌ (cassable par Shor)           | ❌ (cassable par Shor)           |
| **Taille des clés**                | Modérée                          | Plus grande                      | Très grande                      | Petite                          |
| **Vitesse de signature**           | Rapide                           | Rapide                           | Lent                             | Rapide                          |
| **Base mathématique**              | Réseaux euclidiens (Lattice)      | Réseaux euclidiens (Lattice)     | Factorisation de grands nombres  | Courbes elliptiques             |

---

## 🧑‍🔬 L'Algorithme de Shor : La Menace Quantique

### 🔑 Qu'est-ce que l'algorithme de Shor ?
L'algorithme de Shor, développé en 1994 par **Peter Shor**, est un algorithme quantique capable de **factoriser des nombres entiers** en temps polynomial. Cela signifie qu'il peut :  
- **Casser RSA** (basé sur la difficulté de factorisation).  
- **Casser ECC (courbes elliptiques)** en résolvant rapidement les problèmes de logarithmes discrets.  

---

### 🧩 Pourquoi RSA et ECDSA sont vulnérables ?
- **RSA :** Basé sur la difficulté de **factoriser un grand nombre** en ses facteurs premiers.  
- **ECDSA :** Basé sur la difficulté du **logarithme discret** sur les courbes elliptiques.  

L'algorithme de Shor permet de **résoudre ces problèmes très rapidement** avec un ordinateur quantique suffisamment puissant.  

---

### 📉 Complexité de l'Algorithme :
| **Algorithme** | **Complexité Classique**          | **Complexité Quantique (Shor)**  |
|---------------|-----------------------------------|---------------------------------|
| **RSA (n-bits)**   | Exponentielle (`O(2^n)`)           | Polynomial (`O(n^3)`)           |
| **ECC**       | Sous-exponentielle (`O(2^(n/2))`)   | Polynomial (`O(n^3)`)           |

🔹 **RSA 2048 bits** – cassable en quelques heures par un ordinateur quantique.  
🔹 **ECC 256 bits** – cassable en quelques minutes par Shor.  

---

## 🚀 Solution : Cryptographie Post-Quantique (PQC)
Les algorithmes **Kyber** et **Dilithium** sont basés sur des **problèmes de réseaux euclidiens** (Lattice-Based Cryptography), résistants à l'algorithme de Shor.

