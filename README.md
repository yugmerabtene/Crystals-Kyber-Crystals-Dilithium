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
        String secret = "SuperSecretKey12345678";  // 16 bytes for AES-128, 24 for AES-192, 32 for AES-256
        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted = cipher.doFinal("Message secret".getBytes());
        System.out.println("Chiffré : " + Base64.getEncoder().encodeToString(encrypted));
    }
}
```

### 🐍 Exemple Python (AES-256) :
```python
from Crypto.Cipher import AES
import base64

key = b'SuperSecretKey12345678'  # 32 bytes for AES-256
cipher = AES.new(key, AES.MODE_ECB)
message = b'Message secret   '  # Padding to 16 bytes

encrypted = cipher.encrypt(message)
print("Chiffré :", base64.b64encode(encrypted).decode())
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
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());

        byte[] encrypted = cipher.doFinal("Message secret".getBytes());
        System.out.println("RSA Chiffré : " + Base64.getEncoder().encodeToString(encrypted));
    }
}
```

### 🐍 Exemple Python (RSA) :
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

key = RSA.generate(2048)
cipher = PKCS1_OAEP.new(key.publickey())
message = b'Message secret'

encrypted = cipher.encrypt(message)
print("RSA Chiffré :", base64.b64encode(encrypted).decode())
```

---

## 🧬 4. Algorithmes Post-Quantiques (PQC)
### 🔐 Algorithmes Populaires :
- **Crystals-Kyber** : Échange de clés.
- **Crystals-Dilithium** : Signature numérique.
- **Falcon** : Signature plus compacte.

### 📝 Exemple Java (Kyber) :
```java
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import java.security.*;
import java.util.Base64;

public class KyberExample {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber", "BC");
        keyGen.initialize(KyberParameterSpec.kyber512);
        KeyPair keyPair = keyGen.generateKeyPair();
        System.out.println("Clé publique Kyber : " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }
}
```

### 📝 Exemple Java (Dilithium) :
```java
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import java.security.*;
import java.util.Base64;

public class DilithiumExample {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Dilithium", "BC");
        keyGen.initialize(DilithiumParameterSpec.dilithium2);
        KeyPair keyPair = keyGen.generateKeyPair();
        System.out.println("Clé publique Dilithium : " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }
}
```

---

## 🚀 Solution : Cryptographie Post-Quantique (PQC)
Les algorithmes **Kyber** et **Dilithium** sont basés sur des **problèmes de réseaux euclidiens** (Lattice-Based Cryptography), résistants à l'algorithme de Shor.

