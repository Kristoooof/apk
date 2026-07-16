# EP2PC — Encrypted Peer-to-Peer Chat
## Software Architecture & Protocol Specification

| | |
|---|---|
| **Dokumentum verzió** | 0.1 |
| **Státusz** | Draft — folyamatosan bővülő |
| **Utolsó frissítés tárgya** | Development Guide fejezet: build, CI/CD, roadmap — a dokumentáció v0.1 lezárva |

### Dokumentum-térkép

| Fejezet | Cím | Státusz |
|---|---|---|
| EP2PC-001 | Vision & Requirements | ✅ Kész (v0.1) |
| EP2PC-002 | System Architecture | ✅ Kész (v0.1, áttekintés szinten) |
| EP2PC-003 | Networking & Peer Discovery | ✅ Kész (v0.1, részletes) |
| EP2PC-004 | Cryptography Specification | ✅ Kész (v0.1, részletes) |
| EP2PC-005 | Messaging Protocol | ✅ Kész (v0.1, részletes) |
| EP2PC-006 | Group Protocol | ✅ Kész (v0.1, részletes) |
| EP2PC-007 | Storage & Database | ✅ Kész (v0.1, részletes) |
| EP2PC-008 | Android Client | ✅ Kész (v0.1, részletes) |
| EP2PC-009 | Security & Testing | ✅ Kész (v0.1, részletes) |
| EP2PC-010 | Development Guide | ✅ Kész (v0.1, részletes) |
| EP2PC-006 | Group Protocol | ⏳ Tervezett |
| EP2PC-007 | Storage & Database | ⏳ Tervezett |
| EP2PC-008 | Android Client | ⏳ Tervezett |
| EP2PC-009 | Security & Testing | ⏳ Tervezett |
| EP2PC-010 | Development Guide | ⏳ Tervezett |

Ez a dokumentum egy folyamatosan bővíthető specifikáció. Az itt lezárt fejezetek (001–003) véglegesnek tekinthetők a jelenlegi tervezési állapot szerint, de módosíthatók, ha egy későbbi fejezet (pl. Cryptography) új követelményt vezet be, ami visszahat rájuk.

---

# EP2PC-001 — Vision & Requirements

## 1.1 A projekt célja

Az EP2PC (Encrypted Peer-to-Peer Chat) egy teljesen decentralizált, szerver nélküli üzenetküldő rendszer Android eszközök között, amely:

- nem támaszkodik központi üzenetküldő szerverre,
- nem gyűjt vagy tárol felhasználói adatot egyetlen központi helyen sem,
- végpontok között titkosít (E2EE), úgy hogy a hálózat egyetlen közreműködő szereplője (relay, tároló peer, bootstrap node) sem képes elolvasni az üzenetek tartalmát,
- alacsony energiafogyasztás mellett képes órákon, napokon át folyamatosan figyelni a bejövő üzeneteket,
- NAT mögött, port nyitása nélkül is működik,
- támogat csoportos kommunikációt.

## 1.2 Alapelvek

1. **Zéró bizalom a hálózat felé.** Minden olyan szereplő, aki nem a végső címzett, feltételezetten ellenséges lehet. A rendszer biztonsága nem a szereplők jóindulatán, hanem a kriptográfián múlik.
2. **Minimális, de nem nulla infrastruktúra.** A rendszer elfogad egy minimális, jól körülhatárolt, nem-bizalmi infrastruktúra-elemet (bootstrap/relay node) mint a hálózatba lépés technikai feltételét — ez nem üzenetküldő szerver, hanem hálózati belépési pont. Lásd EP2PC-003 §3.5.
3. **Energiatudatosság minden rétegben.** Nincs polling, nincs időzített ébresztés — csak eseményvezérelt (epoll alapú) socket figyelés.
4. **Offline-first.** A rendszer feltételezi, hogy a partner gyakran nincs elérhető állapotban, és erre tervezett mechanizmusa van (store-and-forward), nem pedig kivételkezelés.
5. **A metaadat is adat.** A tervezés nem csak a tartalom titkosítására törekszik, hanem a metaadat-szivárgás (ki kivel, mikor, mekkora üzenetet) minimalizálására is.

## 1.3 Funkcionális követelmények

| ID | Követelmény |
|---|---|
| F-01 | Két felhasználó képes kontaktot felvenni PeerID/nyilvános kulcs QR-kódos cseréjével |
| F-02 | Egy-az-egyben üzenetküldés E2EE-vel |
| F-03 | Csoport létrehozása, tagok meghívása, kilépés, adminjogosultság |
| F-04 | Fájl-, kép-, videó- és hangüzenet küldése, chunkolt átvitellel |
| F-05 | Offline címzett esetén az üzenet ideiglenes, titkosított tárolása a hálózaton (store-and-forward) |
| F-06 | Kézbesítési visszaigazolás (ACK) és a tárolt példány törlése kézbesítés után |
| F-07 | Csoportos LAN-on belüli gyors felfedezés (mDNS) |
| F-08 | Alkalmazás háttérben is folyamatosan fogadóképes marad |

## 1.4 Nem funkcionális követelmények

### Energiafogyasztás
- Nyugalmi (nincs forgalom) állapotban: **0% CPU**, kizárólag eseményvezérelt socket figyelés (epoll), nincs időzített polling.
- Nincs WakeLock, nincs periodikus timer 100ms alatt.
- Cél: több órás/napos háttérműködés érezhető akkumulátor-hatás nélkül.

### Teljesítmény
- Kapcsolatfelépítés (ismert peerrel, cache-elt cím alapján): cél < 2 mp
- Új peer felfedezés DHT-n keresztül: cél < 10 mp
- LAN-on belüli felfedezés (mDNS): cél < 2 mp

### Biztonság
- Végpontok közötti titkosítás minden üzenettípusra (szöveg, fájl, hang) kivétel nélkül
- Forward secrecy és post-compromise security (Double Ratchet)
- Egyetlen közreműködő hálózati szereplő (bootstrap, relay, tároló peer) sem férhet hozzá a tartalomhoz
- Replay-védelem minden üzenetre

### Skálázhatóság
- A rendszernek működnie kell néhány tíz felhasználóval éppúgy, mint több ezerrel, anélkül hogy a hálózati architektúra alapjaiban változna (a bootstrap node szerepe a felhasználószám növekedésével arányosan csökken a DHT önszerveződése miatt — lásd EP2PC-003 §3.5.3).

---

# EP2PC-002 — System Architecture

## 2.1 Magas szintű architektúra

```
┌───────────────────────────────────────────────┐
│                  Android Client                │
│                                                 │
│  ┌───────────────┐        ┌─────────────────┐ │
│  │   Kotlin UI    │◄──────►│  Foreground      │ │
│  │   (Compose)    │  JNI   │  Service         │ │
│  └───────────────┘        └────────┬─────────┘ │
│                                     │            │
│                            ┌────────▼─────────┐ │
│                            │    Rust Core      │ │
│                            │                   │ │
│                            │  libp2p Host      │ │
│                            │  ├─ Noise/TLS     │ │
│                            │  ├─ TCP Transport │ │
│                            │  ├─ Kademlia DHT  │ │
│                            │  ├─ GossipSub     │ │
│                            │  ├─ Identify      │ │
│                            │  ├─ AutoNAT       │ │
│                            │  ├─ DCUtR         │ │
│                            │  └─ Relay Client  │ │
│                            │                   │ │
│                            │  Crypto Layer     │ │
│                            │  ├─ Ed25519       │ │
│                            │  ├─ X25519        │ │
│                            │  └─ Double Ratchet│ │
│                            │                   │ │
│                            │  Storage (SQLCipher)│
│                            └───────────────────┘ │
└───────────────────────────────────────────────┘
```

## 2.2 Rétegek felelőssége

| Réteg | Felelősség |
|---|---|
| Kotlin UI (Compose) | Megjelenítés, felhasználói interakció. Nem tartalmaz üzleti logikát vagy kriptográfiai műveletet. |
| Foreground Service | Az Android életciklusától független futás biztosítása, minimális, folyamatos értesítéssel. |
| JNI interfész | Kotlin ↔ Rust határ. Aszinkron hívások, esemény-callback-ek. |
| Rust Core | Teljes hálózati, kriptográfiai és üzenetkezelési logika. Platformfüggetlen — ez teszi lehetővé a későbbi iOS/desktop portot. |
| Storage | Helyi titkosított adatbázis (SQLCipher), offline queue, cache. |

## 2.3 Identitásmodell

- Minden felhasználói identitás egy **Ed25519 kulcspár**.
- A nyilvános kulcsból (illetve annak hash-éből) származik a **PeerID**, ami egyben a libp2p hálózati azonosító is.
- Nincs telefonszám, nincs email, nincs központi regisztráció.
- Multi-device forgatókönyvben (tervezett, lásd EP2PC-004) egy felhasználó több eszköze ugyanazt az identitást, de eltérő aleszköz-kulcsokat használhatja.

## 2.4 Fő komponensek

| Komponens | Szerepkör |
|---|---|
| libp2p Host | Transport-, titkosítás- és protokollkezelés |
| Kademlia DHT | Peer discovery, provider record-ok tárolása/lekérdezése |
| GossipSub | Csoport-üzenetek terjesztése |
| AutoNAT / DCUtR / Relay | NAT-mögötti elérhetőség biztosítása |
| Double Ratchet modul | Session-kulcsok kezelése, forward secrecy |
| SQLCipher store | Helyi, titkosított perzisztencia |

---

# EP2PC-003 — Networking & Peer Discovery

## 3.1 Transport réteg

- Alapértelmezett transport: **TCP + Noise** (libp2p Noise handshake a TCP fölött).
- WebSocket **nem** kerül használatra Android↔Android kapcsolatokban — felesleges overhead sima TCP mellett.
- **QUIC** opcionálisan engedélyezhető gyorsabb reconnect érdekében, de nem alapértelmezett a projekt jelen fázisában.

## 3.2 Azonosítás és címzés

Minden peer címe **multiaddr** formátumban íródik le, amely tartalmazza a hálózati elérési utat és a kriptográfiailag ellenőrzött PeerID-t:

```
/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWABC...
/dns4/bootstrap.ep2pc.example.com/tcp/4001/p2p/12D3KooWABC...
```

A PeerID a Noise handshake során kriptográfiailag ellenőrzésre kerül — egy támadó nem tud érvényes kapcsolatot hamisítani még akkor sem, ha DNS-szinten (DDNS) sikerülne beavatkoznia, mert nem rendelkezik a célzott PeerID magánkulcsával.

## 3.3 Kontakt hozzáadása (out-of-band csere)

```
Scan (QR-kód)
    │
    ▼
PeerID + nyilvános kulcs
    │
    ▼
Helyi kontaktlista bejegyzés
```

Fontos elvi különbségtétel: a QR-kódos csere csak azt rögzíti, **kit** keresünk (PeerID), nem azt, hogy **hol** érhető el jelenleg. A "hol" kérdést a peer discovery réteg oldja meg dinamikusan, minden kapcsolódási kísérletkor újra.

## 3.4 Peer discovery mechanizmusok

Két, egymást kiegészítő módszer:

### 3.4.1 mDNS (helyi hálózat)

Ha mindkét fél ugyanazon a helyi hálózaton (pl. WiFi) van, mDNS broadcast segítségével azonnal, DHT-lekérdezés nélkül megtalálják egymást. Ez a leggyorsabb és legkevésbé energiaigényes út, ezért mindig ez az elsődlegesen próbált csatorna.

### 3.4.2 Kademlia DHT (WAN)

Ha a felek nincsenek azonos helyi hálózaton, a felderítés a Kademlia DHT-n keresztül történik:

- Minden peer periodikusan közzéteszi a DHT-ban egy **provider record**-ot: `PeerID → jelenlegi elérhető cím(ek)`.
- A DHT-ba **kizárólag** ez a routing-információ kerül. Üzenettartalom, kontaktlista, csoporttagság — semmi ilyen nem kerül a DHT-ba.
- A lekérdezés Kademlia XOR-távolság alapú routinggal fut, elosztottan — nincs egyetlen pont, ami az egész címtárat ismerné.
- A kliens a sikeres lookupokat lokálisan cache-eli, hogy ismételt beszélgetéseknél ne kelljen újra DHT-lookupot indítani.

## 3.5 Bootstrap infrastruktúra

### 3.5.1 Miért szükséges

Egy tisztán elosztott hálózatnak az *első* belépéshez szüksége van legalább egy ismert, elérhető peer címére — ez matematikailag elkerülhetetlen minden P2P rendszerben, amely nem használ központi regisztrációt (ugyanezt a mintát alkalmazza a BitTorrent DHT bootstrap, az IPFS bootstrap peer lista, a Bitcoin DNS seed rendszer és a Tor directory authority modell is).

Ez **nem üzenetküldő szerver**. A bootstrap node:
- nem látja, nem tárolja, nem tudja visszafejteni az üzeneteket,
- nem tudja, mely felhasználók kommunikálnak egymással,
- nem tárol kontaktlistát vagy csoportinformációt,
- kizárólag annyit tesz: ismert peer-címeket ad át egy újonnan csatlakozó kliensnek, hogy az bekapcsolódhasson a DHT-ba.

### 3.5.2 Amit a bootstrap node tud és nem tud

| Tud | Nem tud |
|---|---|
| Új kliens csatlakozott a hálózathoz | Ki a kliens (csak a PeerID-t látja, nem a valós személyt) |
| A saját routing tábláját megosztja | Kivel fog kommunikálni a kliens |
| Részt vesz a DHT-ban (server mode) | Az üzenetek tartalmát |
| — | A kontaktlistát vagy csoporttagságot |

### 3.5.3 Üzemeltetési modell

**Kezdeti fázis:** egyetlen VPS-en futó bootstrap node, DDNS-hez kötött multiaddr-rel:

```
/dns4/bootstrap1.ep2pc.example.com/tcp/4001/p2p/<fix PeerID>
```

Követelmények ezzel a node-dal szemben:

1. **Stabil, perzisztens identitás.** A bootstrap node privát kulcsa soha nem generálódhat újra — ellenkező esetben minden kliensbe hardcode-olt bootstrap cím érvénytelenné válik.
2. **Publikus IP-vel kell rendelkeznie**, kívülről elérhetően — ez a projekt egyetlen olyan komponense, amelyre a "nincs port nyitás" elv nem vonatkozik, mivel ez egy tudatosan vállalt, dedikált szerepkör, nem egy hétköznapi felhasználói eszköz.
3. **DHT "server mode"** engedélyezése — a node aktívan tárol és szolgál ki provider recordokat mások számára is, nem csupán lekérdezőként viselkedik, mint egy telefon.

**A felhasználószám növekedésével** a bootstrap node szerepe fokozatosan csökken: az újonnan csatlakozó kliens a bootstrap node-tól kapott routing-információ alapján saját maga is bekapcsolódik a Kademlia hálózatba, és a további lekérdezéseket már a hozzá XOR-távolságban legközelebbi peerek szolgálják ki — nem szükségszerűen a bootstrap node.

### 3.5.4 Redundancia (tervezett bővítés)

Egyetlen bootstrap node **single point of failure** az *új* csatlakozások szempontjából (a már csatlakozott, egymást ismerő kliensek működése ettől független). Ezért a kezdeti egy node utáni lépésként tervezett:

- 2-3 független bootstrap node (eltérő üzemeltető, eltérő hálózat/geo-lokáció)
- Felhasználó által a beállításokban hozzáadható, saját bootstrap node (`bootstrap-list` konfigurálhatóvá tétele)
- Ez utóbbi erősíti a decentralizációt: a projekt nem válik függővé egyetlen üzemeltetőtől sem.

### 3.5.5 Bootstrap node infrastruktúra-igénye

Minimális — nem futtat üzenetküldő logikát, nincs adatbázis-terhelés jellegű feladata:

- Egyetlen `libp2p` daemon folyamat
- Kis memóriaigény (routing tábla mérete a hálózat méretétől függ, de tipikusan néhányszor tíz MB)
- Alacsony sávszélesség-igény
- Kezdeti fázisban a legkisebb kategóriás VPS is elegendő

## 3.6 NAT traversal (portnyitás nélküli elérhetőség)

Mivel a felhasználók túlnyomó része NAT mögötti mobilhálózaton van, a kapcsolatfelépítés több lépcsős, egymásra épülő fallback-lánc:

```
1. AutoNAT
   └─ megállapítja: publikusan elérhető vagy NAT mögötti a peer

2. Direkt TCP kapcsolódási kísérlet
   └─ siker esetén: direkt kapcsolat, kész

3. DCUtR (hole punching) — ha (2) sikertelen
   └─ mindkét fél egyidejűleg próbál kapcsolódni, egy közvetítő
      koordinálja az időzítést; siker esetén a forgalom innentől
      KÖZVETLENÜL megy, a közvetítő kiesik a folyamatból

4. Circuit Relay v2 — végső fallback, ha (3) is sikertelen
   └─ a forgalom egy relay node-on át folyik; a relay kizárólag
      titkosított byte-okat továbbít, tartalmat nem lát
      (a Noise + Double Ratchet réteg végig aktív)
```

A relay node ugyanazon üzemeltetési modellt követheti, mint a bootstrap node (akár ugyanaz a VPS is elláthatja mindkét szerepet kezdetben).

## 3.7 Store-and-forward (offline üzenetkezelés)

### 3.7.1 Folyamat

```
Küldő
  │
  ▼
Címzett online? ──Igen──► Direkt kézbesítés
  │
  Nem
  │
  ▼
Titkosított üzenet eltárolása
kiválasztott tároló peer(ek)en
  │
  ▼
Címzett online lesz
  │
  ▼
Kézbesítés + ACK
  │
  ▼
Minden tároló peer törli a saját példányát
```

### 3.7.2 Fenyegetéselemzés: mit lát egy tároló peer

| Amit lát | Amit NEM lát / NEM tud |
|---|---|
| Titkosított blob (ciphertext) | Az üzenet tartalma — Double Ratchet miatt egyedi, egyszer használatos kulccsal titkosítva, amihez a tároló peer sosem fér hozzá |
| Küldő és címzett PeerID (metaadat) | A kulcsot a tartalom visszafejtéséhez |
| Timestamp, méret | — |

A tartalom feltörése klasszikus brute-force-szal (ChaCha20-Poly1305 / AES-256-GCM, 2^256 kulcstér) a gyakorlatban soha nem következik be — ez nem "nehéz", hanem a rendelkezésre álló számítási kapacitás mellett kizárt. A valódi kockázat nem a tartalom, hanem a **metaadat**.

### 3.7.3 Hardening intézkedések

| Kockázat | Intézkedés |
|---|---|
| Metaadat-elemzés (ki kivel, mikor, mekkora üzenet) | Rövid TTL + gyors törlés ACK után; hosszabb távon fontolóra veendő "sealed sender"-szerű megoldás, ahol a küldő PeerID is egy réteg mögé kerül |
| Sybil-támadás (támadó sok node-dal célzottan bepozícionálja magát egy adott felhasználó köré) | A tároló peer kiválasztási algoritmusa ne kizárólag XOR-távolság (DHT-közelség) alapú legyen — kerüljön bele randomizált komponens is |
| Cenzúra / üzenet-eldobás (a tároló peer egyszerűen nem továbbítja) | Redundancia: egyszerre több (pl. 3–5), egymástól független tároló peer tárolja ugyanazt az üzenetet |
| Replay (régi ciphertext újraküldése) | Nonce + replay-protection minden üzeneten (részletesen: EP2PC-004) |
| Éleslegesen hosszú tárolás | Rövid TTL (percek / max 1-2 nap), automatikus törlés akkor is, ha nem történt kézbesítés |

Ez a döntéssor tudatosan vállalt trade-off, nem hiányosság — a rendszer biztonsági modellje kriptográfiailag garantálja a tartalom titkosságát *még akkor is*, ha egy tároló peer 100%-ban rosszindulatú; a fenti intézkedések a metaadat-szivárgás elleni további védelmi réteget adják.

### 3.7.4 ACK és törlési protokoll

1. Címzett fogadja és sikeresen visszafejti az üzenetet.
2. Címzett aláírt ACK-ot küld a tároló peer(ek)nek.
3. Tároló peer(ek) az ACK vétele után törlik a saját másolatukat.
4. Ha a TTL lejár ACK nélkül, a tároló peer önállóan, automatikusan törli az üzenetet (nem marad a hálózaton feleslegesen).

## 3.8 Keep-alive stratégia

Fix időzítés helyett **adaptív** keep-alive, hálózattípus szerint, mert a rögzített NAT-timeoutok hálózatonként eltérőek:

| Hálózattípus | Kezdeti keep-alive intervallum |
|---|---|
| WiFi | ~12 perc |
| LTE | ~5 perc |
| 5G | ~5 perc |
| Relay-en keresztüli kapcsolat | ~15 perc |

A rendszer a tényleges NAT-timeout viselkedést megfigyelve dinamikusan állítja az intervallumot (5–20 perc közötti tartományban), a kapcsolat-megszakadások gyakorisága alapján. Sikertelen keep-alive esetén automatikus reconnect indul.

## 3.9 Csoportos kommunikáció — hálózati alapok

*(Részletes protokoll: EP2PC-006)*

- Minden csoport egy **GossipSub topic**-hoz kötött.
- Nem minden tag küld mindenkinek közvetlenül — a GossipSub optimalizálja a terjesztést, korlátozott számú szomszédos peer felé küldve, akik továbbterjesztik.
- A csoport tagsága és a csoportkulcs nem kerül a DHT-ba, csak a topic-résztvevők közötti GossipSub réteget használja.

## 3.10 Fenyegetéselemzés — hálózati réteg összegzés

| Szereplő | Bizalmi szint | Amihez hozzáférhet |
|---|---|---|
| Bootstrap node | Nem bizalmi | Csak: kliens csatlakozott, saját routing tábla megosztása |
| Relay node | Nem bizalmi | Csak: titkosított byte-folyam továbbítása |
| Tároló peer (store-and-forward) | Nem bizalmi | Csak: titkosított blob + metaadat, TTL-lel korlátozva |
| DHT bármely résztvevője | Nem bizalmi | Csak: PeerID → jelenlegi cím leképezés |

Egyik szereplő sem képes az üzenettartalomhoz hozzáférni. A rendszer biztonsági garanciája nem ezen szereplők jóhiszeműségén, hanem a végpontok közötti kriptográfián alapul — ez a tervezés vezérelve minden további fejezetben is (EP2PC-004: Cryptography Specification).

---

# EP2PC-004 — Cryptography Specification

## 4.1 Célok és tervezési elvek

A kriptográfiai réteg a rendszer teljes bizalmi modelljének alapja — minden korábbi fejezetben (EP2PC-003 §3.10) leírt "nem bizalmi szereplő" garancia kizárólag ezen a rétegen múlik. Tervezési célok:

1. **Végpontok közötti titkosság** — semmilyen közreműködő fél (bootstrap, relay, tároló peer) nem férhet hozzá a tartalomhoz.
2. **Forward secrecy** — egy jövőbeli kulcskompromittálódás nem teszi visszafejthetővé a korábbi üzeneteket.
3. **Post-compromise security** — egy múltbeli kulcskompromittálódás után a rendszer képes "önmagát meggyógyítani", azaz a jövőbeli üzenetek újra biztonságossá válnak, amint friss kulcsanyag kerül becsatornázásra.
4. **Hitelesség és integritás** — minden üzenet ellenőrizhetően az állítólagos küldőtől származik, és nem módosítható észrevétlenül.
5. **Replay-védelem** — egy elfogott, korábban már kézbesített üzenet nem játszható le újra érvényesként.
6. **Minimális kriptográfiai felület** — kevés, jól auditált primitív, ismétlődő felhasználással, ahelyett hogy sok különböző algoritmus keveredne.

## 4.2 Primitívek áttekintése

| Cél | Primitív |
|---|---|
| Identitás / aláírás | Ed25519 |
| Kulcscsere (session létrehozás) | X25519 (Diffie–Hellman) |
| Kulcsderiválás | HKDF (SHA-256 alapú) |
| Szimmetrikus titkosítás | ChaCha20-Poly1305 (elsődleges) vagy AES-256-GCM (hardver-gyorsítás esetén) |
| Session-kulcs evolúció | Double Ratchet (Signal-protokoll alapú) |
| Hash | SHA-256 |

Az elsődleges szimmetrikus algoritmus **ChaCha20-Poly1305**, mert szoftveresen is gyors és konstans idejű, AES hardveres gyorsítás nélküli eszközökön (sok belépő szintű Android telefon) is egyenletes teljesítményt nyújt. Ahol az eszköz AES-NI-szerű hardveres gyorsítással rendelkezik, az implementáció átválthat AES-256-GCM-re — a protokollszinten mindkettő azonos kulcs- és nonce-hosszal, felcserélhető módon kezelendő, a választott algoritmus az üzenet fejlécében jelölve.

## 4.3 Identitáskulcsok (Ed25519)

- Minden felhasználói identitás egy Ed25519 kulcspár: a nyilvános kulcsból származik a PeerID (EP2PC-002 §2.3, EP2PC-003 §3.2).
- Az identitáskulcs **soha nem** kerül közvetlenül titkosításra használatra — kizárólag aláírásra (session-indítás hitelesítése, ACK-ok aláírása, provider recordok hitelesítése a DHT-ban).
- A privát identitáskulcs az eszközön, a helyi titkosított tárolóban (SQLCipher, lásd EP2PC-007) marad, hálózaton soha nem hagyja el az eszközt.
- Multi-device forgatókönyv (tervezett bővítés): az elsődleges identitáskulcs aláír egy eszköz-specifikus alkulcsot ("device key"), amivel az adott eszköz önállóan tud kommunikálni — így egy eszköz elvesztése nem kompromittálja a teljes identitást, csak az adott alkulcsot kell visszavonni.

## 4.4 Session létrehozás — kezdeti kulcscsere

Az első üzenetváltás előtt a két fél egy X3DH-szerű (Extended Triple Diffie-Hellman) kezdeti kulcscserét hajt végre, amely a hosszútávú Ed25519 identitáson túl X25519 efemer kulcsokat is felhasznál:

```
Küldő (A)                                   Címzett (B)
    │                                             │
    │   A ismeri B PeerID-jét és nyilvános         │
    │   identitáskulcsát (QR-kódos csere, §3.3)    │
    │                                             │
    │──── X25519 DH(A_identitás, B_identitás) ────│
    │──── X25519 DH(A_efemer,   B_identitás) ────│
    │──── X25519 DH(A_identitás, B_efemer)   ────│
    │                                             │
    ▼                                             ▼
   HKDF(összes DH kimenet) → kezdeti Root Key
```

A kezdeti Root Key innentől a Double Ratchet bemenete (§4.5). Ez a lépés csak **egyszer** történik meg egy adott kontakt-párnál — utána a Double Ratchet önállóan, folyamatosan új kulcsokat generál minden további üzenethez, új kulcscsere-tranzakció nélkül.

## 4.5 Double Ratchet — session-kulcsok evolúciója

A Double Ratchet (Signal-protokoll) biztosítja, hogy:

- **minden egyes üzenet** saját, egyedi, egyszer használatos titkosítókulccsal (message key) legyen titkosítva,
- egy adott message key kompromittálódása **ne** tegye visszafejthetővé sem a korábbi, sem a későbbi üzeneteket (forward secrecy + post-compromise security).

```
                Root Key
                   │
        ┌──────────┴──────────┐
        │                     │
   Sending Chain         Receiving Chain
        │                     │
        ▼                     ▼
   Message Key 1         Message Key 1
   Message Key 2         Message Key 2
   Message Key 3         Message Key 3
        │                     │
   (minden üzenet után      (minden fogadott
    a chain "forog",         üzenet után a
    új kulcs generálódik)    chain "forog")
```

Minden alkalommal, amikor a küldő fél új DH-efemer kulcsot kap a partnertől (ez rendszeresen megtörténik, tipikusan minden válasz-üzenetnél), egy **DH ratchet lépés** is végrehajtódik, ami friss entrópiát vezet be a Root Key-be — ez adja a post-compromise security tulajdonságot: ha egy támadó egy pillanatra hozzáfért egy kulcshoz, a következő DH ratchet lépés után a rendszer "kigyógyul" ebből.

A tároló peer (store-and-forward, EP2PC-003 §3.7) számára ez azt jelenti: még ha egyszerre több titkosított üzenetet is tárol ugyanattól a küldőtől, mindegyiket **különböző** kulccsal titkosították — egyetlen kulcs megszerzése (ami eleve nem lehetséges a tároló peer számára) sem tenné olvashatóvá a többi üzenetet.

## 4.6 HKDF — kulcsderiválás

Minden ponton, ahol nyers DH-kimenetből vagy Root Key-ből további kulcsanyagot kell származtatni (chain key, message key, header key), **HKDF (SHA-256)** kerül alkalmazásra, kontextusfüggő "info" paraméterrel, hogy azonos bemenetből soha ne generálódjon véletlenül azonos kulcs két különböző célra.

## 4.7 Szimmetrikus titkosítás és nonce-kezelés

- Az üzenet payload titkosítása: **ChaCha20-Poly1305** (vagy AES-256-GCM, §4.2 szerint), AEAD módban — ez egyszerre biztosít titkosságot és integritást (hitelesített titkosítás).
- **Nonce**: minden üzenethez egyedi, monoton növekvő számláló + session-azonosító kombinációjából származik — soha nem használódik újra ugyanazon kulccsal.
- **Replay-védelem**: a fogadó fél nyilvántartja a legutóbb elfogadott üzenet-sorszámokat (sliding window, a Double Ratchet skipped message key kezelésével összhangban); egy korábban már feldolgozott sorszámú üzenet automatikusan elutasításra kerül.

## 4.8 Az üzenet kriptográfiai boríték-szerkezete

```
EncryptedMessage {
  sender_id        // küldő PeerID
  session_id       // Double Ratchet session azonosító
  ratchet_header    // aktuális DH-nyilvános kulcs, chain-index (titkosítatlan,
                     // de a header maga is védett kulccsal — "header encryption")
  nonce
  ciphertext        // AEAD-titkosított payload
  auth_tag          // AEAD hitelesítő tag (Poly1305 vagy GCM tag)
}
```

Ez a struktúra közvetlenül megfelel az EP2PC-003 §3.7.2-ben leírt "amit egy tároló peer lát" táblázatnak: a `ratchet_header`, `nonce` és metaadat-mezők (sender/session ID) látszanak, de a `ciphertext` visszafejtéséhez szükséges kulcs sosem kerül a hálózatra.

## 4.9 Csoport kulcskezelés

- Minden csoporthoz tartozik egy **Group Key**, amelyet X25519 alapú páronkénti kulcscserével juttatnak el az új tagoknak belépéskor.
- A csoportüzenetek titkosítása a Group Key-ből származtatott, folyamatosan rotálódó kulcsokkal történik (a rotáció triggerei: új tag belépése, tag kilépése/eltávolítása, illetve időszakos, tervezett rotáció).
- **Tag eltávolítása / kilépés esetén kötelező azonnali kulcsrotáció** — enélkül a kizárt tag a régi kulccsal továbbra is olvashatná a jövőbeli üzeneteket (ez sérti a post-compromise/forward secrecy elvet csoportos kontextusban is).
- A részletes csoportprotokoll (meghívás, adminjogok, GossipSub-integráció): EP2PC-006.

## 4.10 Kulcstárolás és -védelem az eszközön

- A hosszútávú identitáskulcs és az aktív session-állapotok (ratchet state) a helyi SQLCipher-adatbázisban, titkosítva tárolódnak (részletes séma: EP2PC-007).
- A titkosított adatbázis kulcsa az Android Keystore-ban (hardver-támogatott biztonsági elem, ahol elérhető) kerül tárolásra, nem a fájlrendszeren.
- A privát kulcsanyag soha nem hagyja el a Rust Core memóriaterét titkosítatlan formában, és a JNI-határon átadott adatokból kulcsanyag nem kerülhet át a Kotlin/UI rétegbe.

## 4.11 Fenyegetéselemzés — kriptográfiai réteg összegzés

| Támadási forgatókönyv | Védelem |
|---|---|
| Passzív lehallgatás a hálózaton (bootstrap, relay, tároló peer) | AEAD titkosítás — tartalom hozzáférhetetlen |
| Egy session-kulcs kompromittálódik | Forward secrecy — korábbi üzenetek nem fejthetők vissza |
| Egy hosszabb távú kulcs pillanatnyi kompromittálódása | Post-compromise security — a Double Ratchet DH-lépései "kigyógyítják" a rendszert |
| Üzenet visszajátszása (replay) | Sorszám-alapú sliding window + AEAD nonce-egyediség |
| Man-in-the-middle a session-indításnál | Ed25519-alapú identitás-hitelesítés az X3DH-szerű handshake-ben |
| Kizárt csoporttag további olvasása | Kötelező azonnali Group Key rotáció kilépés/eltávolítás esetén |

---

# EP2PC-005 — Messaging Protocol

## 5.1 Célok és áttekintés

Ez a fejezet írja le, hogy a végpontok közötti titkosítási réteg (EP2PC-004) fölött milyen **alkalmazásszintű üzenettípusok** léteznek, hogyan szerializálódnak a hálózaton, és milyen életciklust futnak be küldéstől a kézbesítésig, illetve szerkesztésig/törlésig. A réteg célja:

1. Kompakt, kis overhead-ű szerializáció (energiafogyasztási cél, EP2PC-001 §1.4).
2. Egységes üzenetkeret minden tartalomtípusra (szöveg, csatolmány, hangüzenet, rendszerüzenet).
3. Megbízható kézbesítés bizonytalan hálózati körülmények között (retry, chunkolás).
4. Szerkesztés/törlés úgy, hogy az visszamenőlegesen is konzisztens maradjon minden résztvevő eszközén.

## 5.2 Szerializáció: Protocol Buffers

- A JSON helyett **Protocol Buffers (protobuf)** kerül alkalmazásra minden hálózaton átmenő struktúrára.
- Indoklás: bináris, séma-vezérelt, jelentősen kisebb méret és kevesebb CPU-igényű parse/serialize, mint a szöveges JSON — ez közvetlenül az energiafogyasztási célt szolgálja (EP2PC-001 §1.4).
- Minden `.proto` séma verziózott (`ep2pc.messaging.v1` névtér), hogy a protokoll később bővíthető legyen visszafelé kompatibilis módon (`reserved` mezőszámok, opcionális mezők).

## 5.3 Üzenettípusok

| Típus | Kód | Leírás |
|---|---|---|
| `TEXT` | 0x01 | Egyszerű szöveges üzenet |
| `EDIT` | 0x02 | Korábbi üzenet szerkesztése |
| `DELETE` | 0x03 | Korábbi üzenet törlése |
| `ATTACHMENT` | 0x04 | Fájl/kép/videó csatolmány (chunkolt) |
| `VOICE` | 0x05 | Hangüzenet (Opus kódolással) |
| `READ_RECEIPT` | 0x06 | Olvasási visszaigazolás (opcionális, kikapcsolható) |
| `DELIVERY_ACK` | 0x07 | Kézbesítési visszaigazolás (store-and-forward törléshez, EP2PC-003 §3.7.4) |
| `GROUP_CONTROL` | 0x08 | Csoport-vezérlő üzenet (meghívás, kilépés, kulcsrotáció — részletes: EP2PC-006) |
| `TYPING` | 0x09 | Gépelés-jelzés (opcionális, best-effort, nem garantált kézbesítésű) |

## 5.4 Alap üzenetstruktúra (protobuf váz)

```protobuf
syntax = "proto3";
package ep2pc.messaging.v1;

message Envelope {
  bytes  message_id      = 1;  // 16 byte, véletlenszerű
  uint32 type             = 2;  // §5.3 típuskód
  bytes  conversation_id  = 3;  // 1:1 vagy csoport azonosító
  int64  timestamp        = 4;  // küldő oldali, csak tájékoztató jellegű
  bytes  payload          = 5;  // típus-specifikus, EP2PC-004 §4.8 szerint titkosítva
  bytes  reply_to         = 6;  // opcionális, válasz-üzenet esetén
}

message TextPayload {
  string body = 1;
}

message EditPayload {
  bytes  target_message_id = 1;
  string new_body          = 2;
}

message DeletePayload {
  bytes target_message_id = 1;
  bool  delete_for_everyone = 2; // false = csak lokális törlés
}
```

Fontos: az `Envelope.payload` mező mindig az EP2PC-004 §4.8-ban leírt titkosított boríték tartalma — a fenti `TextPayload`, `EditPayload` stb. struktúrák a **visszafejtés utáni**, tiszta protobuf-tartalmat írják le. A hálózaton soha nem jár nyílt szövegű protobuf, kizárólag a titkosított `ciphertext`.

## 5.5 Szöveges üzenet életciklusa

```
Elkészül (UI)
     │
     ▼
Titkosítás (EP2PC-004)
     │
     ▼
   Küldés
     │
 ┌───┴────┐
 │        │
Sikeres  Sikertelen
 │        │
 │        ▼
 │     Retry-sor (§5.10)
 │
 ▼
Címzett fogadja, visszafejti
     │
     ▼
DELIVERY_ACK küldése a küldőnek
     │
     ▼
(opcionális) READ_RECEIPT, ha a felhasználó
beállításai engedélyezik
```

Az üzenet UI-státusza (`küldve` → `kézbesítve` → `olvasva`) ezen visszaigazolások alapján frissül. Az `olvasva` állapot **teljes mértékben opcionális** és felhasználói beállításban kikapcsolható — kikapcsolt állapotban a `READ_RECEIPT` üzenettípus egyáltalán nem kerül elküldésre.

## 5.6 Szerkesztés (Edit)

- Egy `EDIT` üzenet egy korábbi `message_id`-re hivatkozik, és tartalmazza az új szöveget.
- A fogadó kliens a helyi adatbázisban (EP2PC-007) az eredeti üzenet mellett megőrzi a szerkesztési előzményt (nem írja felül visszavonhatatlanul), hogy a UI jelezhesse: *"szerkesztve"*.
- Csak a **saját** korábbi üzenete szerkeszthető — ezt a Double Ratchet session-höz kötött feladó-hitelesítés (EP2PC-004 §4.7) garantálja: egy `EDIT` payload csak akkor fogadható el, ha ugyanattól a feladó-identitástól érkezik, mint az eredeti üzenet.
- Csoportban az `EDIT` a `GossipSub` topicon terjed, ugyanúgy, mint az eredeti üzenet.

## 5.7 Törlés (Delete)

Két mód:

| Mód | Hatás |
|---|---|
| Lokális törlés | Csak a küldő saját eszközén tűnik el az üzenet, hálózati üzenet nem is generálódik |
| "Törlés mindenkinél" (`delete_for_everyone = true`) | `DELETE` üzenet kerül szétküldésre; minden fogadó kliens a helyi másolatot lecseréli egy "üzenet törölve" jelzésre |

Fontos korlát, amit a dokumentációban is rögzíteni kell: a "törlés mindenkinél" **nem tud garanciát vállalni** arra, hogy a címzett még nem olvasta el, vagy nem mentette le képernyőképként — ez minden végpontok-közötti titkosított rendszer velejáró korlátja, nem az EP2PC hiányossága.

## 5.8 Olvasási visszaigazolás (Read Receipt)

- Alapértelmezésben **kikapcsolt** állapotot javaslunk (privacy-first megközelítés, összhangban EP2PC-001 §1.2 "zéró bizalom" elvével) — a felhasználó saját döntése alapján kapcsolható be.
- Ha be van kapcsolva, a `READ_RECEIPT` üzenet ugyanazon E2EE session-en megy, mint bármely más üzenet — a hálózat egyetlen közreműködője sem tud belőle metaadatot kinyerni azon túl, amit egyébként is lát (EP2PC-003 §3.7.2).

## 5.9 Csatolmányok és chunkolás

- Nagyméretű tartalom (kép, videó, fájl) nem kerül egyben átküldésre.
- **Chunkméret: 64 KB**, párhuzamos streamekben küldve libp2p stream-eken keresztül.
- Minden chunk önállóan hitelesített (AEAD tag, EP2PC-004 §4.7) — egy sérült/manipulált chunk elutasításra kerül anélkül, hogy az egész átvitelt újra kellene kezdeni.

```
Fájl (pl. 1 MB)
     │
     ▼
Szeletelés: 64 KB chunk-ok
     │
     ▼
Minden chunk külön titkosítva + hitelesítve
     │
     ▼
Párhuzamos küldés (libp2p stream-multiplexing)
     │
     ▼
Fogadó oldali újraösszeállítás + integritás-ellenőrzés
```

Sikertelen chunk esetén csak az adott chunk kerül újraküldésre (§5.10), nem a teljes fájl.

## 5.10 Hangüzenetek

- Kódolás: **Opus**, mert minden célplatformon (Android, iOS, Windows, Linux, macOS) elérhető, alacsony bitrátán is jó minőségű, és alacsony a kódolási/dekódolási CPU-igénye.
- A hangüzenet a csatolmány-mechanizmuson (§5.9) keresztül kerül átvitelre, `VOICE` típusjelöléssel, hogy a UI külön lejátszó-felületet társítson hozzá időtartam-metaadattal.

## 5.11 Retry és hibakezelés

| Hiba | Kezelés |
|---|---|
| Címzett offline | Automatikus átirányítás store-and-forward-ra (EP2PC-003 §3.7) |
| Kapcsolat megszakad küldés közben | Exponenciális backoff alapú retry, korlátozott próbálkozásszámmal |
| Chunk-szintű sérülés/hitelesítési hiba | Csak az érintett chunk újraküldése (§5.9) |
| Session-inkonzisztencia (pl. ratchet-state eltérés) | Session-újraindítás egy friss X3DH-szerű handshake-kel (EP2PC-004 §4.4) |

Retry közben a rendszer nem tartja ébren feleslegesen a rádiót/CPU-t — a backoff-időzítés az eseményvezérelt socket-modellbe illeszkedik (EP2PC-003 §3.8 keep-alive logikájával összehangoltan), nem önálló polling-mechanizmusként fut.

## 5.12 Megjegyzés a metaadat-minimalizáláshoz

Az `Envelope` fejléc (`conversation_id`, `type`, `timestamp`) szükségszerűen kevesebb védelmet élvez, mint a `payload` tartalma, mert a routing-hoz és a store-and-forward mechanizmushoz (EP2PC-003 §3.7) egyes mezőknek látszaniuk kell a köztes szereplők számára is. Ez tudatosan vállalt trade-off, ugyanazon elvek mentén, mint amit a EP2PC-003 §3.7.3 hardening-táblázata rögzít — a `payload` tartalma minden körülmények között hozzáférhetetlen marad a köztes szereplők számára.

---

# EP2PC-006 — Group Protocol

## 6.1 Célok és áttekintés

Ez a fejezet a csoportos kommunikáció teljes protokollját írja le: a csoport adatmodelljét, a szerepköröket, a tagfelvétel/kilépés folyamatát és a csoportkulcs-kezelés állapotgépét. A hálózati alapokat (GossipSub topic-modell) az EP2PC-003 §3.9 már lefektette, a kriptográfiai alapelveket (Group Key, kötelező rotáció kilépéskor) az EP2PC-004 §4.9 — ez a fejezet ezekre épül, és a teljes, végponttól végpontig terjedő protokollt specifikálja.

Tervezési elv: a csoport **nem egy szerveren nyilvántartott entitás**, hanem egy elosztott állapot, amit minden tag saját maga, önállóan tart karban a kapott vezérlő-üzenetek (`GROUP_CONTROL`, EP2PC-005 §5.3) alapján.

## 6.2 Csoport adatmodell

```protobuf
syntax = "proto3";
package ep2pc.group.v1;

message GroupMetadata {
  bytes  group_id       = 1;  // 16 byte, létrehozáskor generált véletlenszám
  string display_name   = 2;
  bytes  creator_peer_id = 3;
  int64  created_at      = 4;
  uint32 key_epoch        = 5;  // aktuális csoportkulcs-generáció sorszáma
}

message GroupMember {
  bytes  peer_id     = 1;
  bool   is_admin      = 2;
  int64  joined_at     = 3;
  uint32 joined_epoch  = 4;  // melyik kulcs-generációtól tag
}
```

- A `group_id` egy véletlenszerű azonosító — **nem** származtatható a tagok PeerID-jéből, hogy ne legyen kikövetkeztethető a csoport összetétele a topic-névből.
- A `GossipSub` topic neve maga a `group_id` egy hash-elt formája, nem a nyers érték — ez extra réteget ad a topic-alapú korrelációs támadások ellen.

## 6.3 Szerepkörök és jogosultságok

| Szerepkör | Jogosultságok |
|---|---|
| **Admin** | Tag meghívása, tag eltávolítása, admin-jog átadása, csoportnév módosítása, csoport feloszlatása |
| **Member (tag)** | Üzenetküldés, saját kilépés, csoport-metaadat olvasása |

- A csoport létrehozója automatikusan az első admin.
- **Több admin is lehet egyszerre** — a jogosultság nem kizárólagos.
- Minden admin-műveletet a végrehajtó Ed25519 identitáskulcsa ír alá (EP2PC-004 §4.3) — egy `GROUP_CONTROL` üzenet csak akkor fogadható el érvényesként, ha az aláíró a küldés pillanatában admin-jogosultsággal rendelkezett a tagok helyi állapota szerint.

## 6.4 GossipSub integráció

Amint azt az EP2PC-003 §3.9 lefektette, minden csoport egy GossipSub topic-hoz kötött. Ezen a rétegen pontosítva:

- A topic-hoz csak azok a peer-ek csatlakoznak, akik a csoportkulcsot (§6.6) ismerik — a GossipSub réteg maga nem végez hozzáférés-ellenőrzést, ez a **kriptográfia feladata**: aki nem ismeri az aktuális Group Key-t, az a titkosított üzeneteket látja ugyan a topicon (ha csatlakozna hozzá), de nem tudja visszafejteni.
- A tényleges hozzáférés-védelem tehát nem a GossipSub-szinten, hanem a titkosítási rétegen valósul meg — ez szándékos tervezési döntés, mert a GossipSub topic-tagság önmagában nem tekinthető megbízható jogosultság-ellenőrzésnek egy nyílt overlay hálózaton.

## 6.5 Csoport létrehozása

```
Létrehozó (Admin)
     │
     ▼
GroupMetadata generálása (group_id, key_epoch = 0)
     │
     ▼
Kezdeti Group Key generálása (X25519-ből származtatva)
     │
     ▼
GossipSub topic feliratkozás (hash(group_id))
     │
     ▼
Kész — a létrehozó az egyetlen tag, epoch 0
```

## 6.6 Meghívás folyamata

```
Admin                                    Meghívott
  │                                          │
  │── GROUP_CONTROL: INVITE ────────────────►│
  │   (GroupMetadata + aktuális Group Key,   │
  │    az admin és a meghívott közötti        │
  │    1:1 E2EE session-en küldve,             │
  │    EP2PC-004 §4.4 szerint)                 │
  │                                          │
  │                                          ▼
  │                                   Meghívott elfogadja
  │                                          │
  │◄──── GROUP_CONTROL: JOIN_ACK ────────────│
  │                                          │
  ▼                                          ▼
Minden tag frissíti a                  GossipSub topic-ra
GroupMember listát                     feliratkozás
```

Fontos: a Group Key átadása **soha nem** a GossipSub topicon keresztül történik (hiszen azt csak a már bent lévő tagok tudnák visszafejteni), hanem egy dedikált, 1:1 E2EE session-en, admin és meghívott között — ugyanazon Double Ratchet-mechanizmussal, mint bármely más privát üzenet.

## 6.7 Kilépés és eltávolítás

| Esemény | Folyamat |
|---|---|
| Tag önként kilép | `GROUP_CONTROL: LEAVE` üzenet a topicra → minden tag eltávolítja a listájából → **kötelező kulcsrotáció** (§6.8) |
| Admin eltávolít egy tagot | `GROUP_CONTROL: REMOVE(peer_id)`, admin aláírással → minden tag eltávolítja a listájából → **kötelező kulcsrotáció** (§6.8) |
| Utolsó admin kilép, marad tag | A csoport automatikusan admin nélkül marad — a kliens UI-szinten javasolja admin-jog átadását kilépés előtt; ha ez elmarad, a csoport "árva" állapotba kerül (tagok tudnak írni, de senki nem tud új tagot meghívni vagy eltávolítani) |

A kötelező kulcsrotáció mindkét esetben ugyanaz az ok miatt szükséges, amit az EP2PC-004 §4.9 már rögzített: a kilépett/eltávolított tag birtokában lévő régi Group Key-vel a jövőbeli üzenetek nem maradhatnak olvashatók.

## 6.8 Csoportkulcs-rotáció állapotgépe

```
                epoch = N
                    │
        ┌───────────┴───────────┐
        │                       │
   Tag belép              Tag kilép/eltávolítva
        │                       │
        ▼                       ▼
   Új Group Key generálása (epoch = N+1)
                    │
                    ▼
   Az új kulcs szétküldése minden AKTUÁLIS tagnak,
   egyenként, 1:1 E2EE session-ökön (§6.6 mintája szerint)
                    │
                    ▼
   Minden tag frissíti a helyi key_epoch-ot
                    │
                    ▼
   Ez a pillanattól az összes csoportüzenet
   epoch = N+1 kulccsal titkosított
```

- Az eltávolított/kilépett tag **nem** kap új kulcsot — ez garantálja, hogy a rotáció utáni üzeneteket nem tudja visszafejteni.
- A régi (epoch = N) kulcs a tagoknál csak a **korábbi**, még el nem olvasott üzenetek visszafejtéséhez marad meg átmenetileg, majd törlődik (összhangban a forward secrecy elvvel).

## 6.9 Adminisztrációs jogkiosztás

```protobuf
message GroupControlPayload {
  enum Action {
    INVITE        = 0;
    JOIN_ACK      = 1;
    LEAVE         = 2;
    REMOVE        = 3;
    GRANT_ADMIN   = 4;
    REVOKE_ADMIN  = 5;
    RENAME        = 6;
    KEY_ROTATION  = 7;
  }
  Action action        = 1;
  bytes  target_peer_id = 2;  // ahol releváns (REMOVE, GRANT_ADMIN stb.)
  bytes  group_id       = 3;
  uint32 key_epoch       = 4;
}
```

Minden `GROUP_CONTROL` üzenet a fenti struktúrát hordozza payloadként (EP2PC-005 §5.3 `GROUP_CONTROL` típusán belül), a küldő Ed25519-aláírásával hitelesítve.

## 6.10 Fenyegetéselemzés — csoportréteg

| Támadási forgatókönyv | Védelem |
|---|---|
| Kizárt tag megpróbálja tovább olvasni az üzeneteket | Kötelező kulcsrotáció kilépéskor/eltávolításkor (§6.8) |
| Nem-admin tag hamis `REMOVE`/`INVITE` üzenetet küld | Aláírás-ellenőrzés + helyi admin-lista alapján érvénytelenítve |
| Csoport-összetétel kikövetkeztetése a topic-névből | Hash-elt topic-azonosító (§6.2) |
| Replay egy korábbi `GROUP_CONTROL` üzenettel (pl. régi `INVITE` újraküldése) | `key_epoch` mező + a §4.7-ben leírt replay-védelmi mechanizmus alkalmazandó csoportüzenetekre is |
| Admin fiók kompromittálódása | Több admin támogatása csökkenti az egyetlen ponton történő kompromittálódás hatását; a admin-jog visszavonható más admin által |

---

# EP2PC-007 — Storage & Database

## 7.1 Célok és áttekintés

Ez a fejezet írja le, hogyan tárolódik minden helyi adat az eszközön: az üzenetek, kontaktok, csoportok, kriptográfiai session-állapotok, csatolmányok és a kimenő üzenetek várólistája. Tervezési célok:

1. **Minden perzisztens adat titkosítva legyen a lemezen** — egy elveszett/ellopott eszköz ne jelentsen adatvesztést.
2. **A titkosított adatbázis kulcsa hardver-támogatott biztonsági elemben** legyen, ne a fájlrendszeren.
3. **Offline-first működés** — a kimenő üzenetek várólistája (EP2PC-005 §5.11 retry-logikájával összhangban) is perzisztens, egy alkalmazás-újraindítás ne veszítsen el üzeneteket.
4. **Kontrollált gyorsítótár-növekedés** — cache-elt tartalom (avatar, thumbnail) ne nőjön korlátlanul.

## 7.2 SQLCipher — technológiai választás

- Az alap adattár **SQLite + SQLCipher** kiterjesztés, ami transzparens, teljes adatbázis-szintű titkosítást ad (AES-256, összhangban EP2PC-004 §4.2 primitív-választásával).
- Indoklás Room helyett/mellett: a projekt Rust Core-alapú (EP2PC-002 §2.2), ezért az adatbázis-réteg natívan, a Rust oldalon (pl. `rusqlite` + SQLCipher binding) valósul meg, nem a Kotlin/Room rétegben — ez konzisztens az architektúra elvével, hogy minden üzleti logika és állapot a platformfüggetlen Core-ban él, elősegítve a későbbi iOS-portot (EP2PC-002 §2.2, EP2PC-001 vízió).
- A titkosítási kulcs az **Android Keystore**-ban tárolódik (hardveres biztonsági elem, ahol az eszköz támogatja), nem magában az adatbázis-fájlban vagy a `SharedPreferences`-ben.

## 7.3 Adatbázis séma (áttekintés)

```sql
CREATE TABLE contacts (
  peer_id           BLOB PRIMARY KEY,
  display_name      TEXT,
  public_key         BLOB NOT NULL,
  added_at           INTEGER NOT NULL
);

CREATE TABLE conversations (
  conversation_id    BLOB PRIMARY KEY,
  is_group           INTEGER NOT NULL,   -- 0 = 1:1, 1 = csoport
  group_id            BLOB,               -- NULL, ha nem csoport
  last_activity_at    INTEGER
);

CREATE TABLE messages (
  message_id         BLOB PRIMARY KEY,
  conversation_id     BLOB NOT NULL REFERENCES conversations(conversation_id),
  sender_peer_id      BLOB NOT NULL,
  type                 INTEGER NOT NULL,   -- EP2PC-005 §5.3 típuskód
  body                 TEXT,               -- csak TEXT típusnál
  attachment_ref       BLOB,               -- FK, ha van csatolmány
  edited               INTEGER DEFAULT 0,
  deleted              INTEGER DEFAULT 0,
  sent_at              INTEGER NOT NULL,
  delivered_at         INTEGER,
  read_at               INTEGER
);

CREATE TABLE groups (
  group_id            BLOB PRIMARY KEY,
  display_name         TEXT,
  key_epoch             INTEGER NOT NULL,
  created_at            INTEGER NOT NULL
);

CREATE TABLE group_members (
  group_id            BLOB NOT NULL REFERENCES groups(group_id),
  peer_id              BLOB NOT NULL,
  is_admin              INTEGER NOT NULL,
  joined_epoch          INTEGER NOT NULL,
  PRIMARY KEY (group_id, peer_id)
);

CREATE TABLE sessions (
  peer_id              BLOB PRIMARY KEY,
  ratchet_state         BLOB NOT NULL,   -- szerializált Double Ratchet állapot
  updated_at            INTEGER NOT NULL
);

CREATE TABLE outbound_queue (
  message_id           BLOB PRIMARY KEY,
  conversation_id       BLOB NOT NULL,
  payload                BLOB NOT NULL,
  retry_count            INTEGER DEFAULT 0,
  next_retry_at          INTEGER,
  created_at             INTEGER NOT NULL
);

CREATE INDEX idx_messages_conversation_ts ON messages(conversation_id, sent_at);
CREATE INDEX idx_messages_id ON messages(message_id);
CREATE INDEX idx_outbound_next_retry ON outbound_queue(next_retry_at);
```

Ez a séma a jelen fázis alapváza — a fejlesztés során bővülhet (pl. `read_receipts` külön tábla, ha a csoportos olvasási állapotot is finomabban kell követni), de a fő entitások (kontakt, beszélgetés, üzenet, csoport, session, kimenő várólista) itt rögzítettek.

## 7.4 Kulcsanyag tárolása

- A `sessions.ratchet_state` mező tartalmazza a Double Ratchet aktuális állapotát (chain key-ek, DH-kulcspárok) — ez a **legérzékenyebb** tábla, hiszen ebből származtatható a jövőbeli üzenetek kulcsa.
- Az identitáskulcs (Ed25519 privát kulcs) **nem** ebben a táblában, hanem külön, az Android Keystore-hoz közvetlenül kötött tárolóban él, ahol az eszköz ezt támogatja (hardver-alapú kulcstárolás, amely a kulcsot soha nem engedi ki olvasható formában az alkalmazás memóriaterébe sem).
- Részletek: EP2PC-004 §4.10.

## 7.5 Offline queue (kimenő üzenetek várólistája)

```
Üzenet küldése indul
        │
        ▼
Beszúrás az outbound_queue táblába
        │
        ▼
Küldési kísérlet ──── Sikeres ────► Törlés az outbound_queue-ból
        │
    Sikertelen
        │
        ▼
retry_count++, next_retry_at frissítése
(exponenciális backoff, EP2PC-005 §5.11)
        │
        ▼
Alkalmazás-újraindítás esetén is megmarad —
a Foreground Service indulásakor újraolvassa
a táblát és folytatja a retry-ciklust
```

Ez biztosítja, hogy egy alkalmazás-leállás (pl. eszköz-újraindítás) ne okozzon üzenetvesztést — a várólista perzisztens, nem csak memóriában él.

## 7.6 Fájl- és képtárolás

- A csatolmányok (kép, videó, fájl, hangüzenet) **nem** kerülnek be az SQLCipher adatbázisba blob-ként — helyette a fájlrendszeren, külön, titkosított formában tárolódnak (fájlszintű titkosítás, ugyanazon kulcs-hierarchia alá tartozva, mint az adatbázis).
- Az adatbázis csak egy hivatkozást (`attachment_ref`) és metaadatot (méret, típus, hash) tárol — ez elkerüli, hogy nagy bináris tartalom terhelje az adatbázis-motort, és gyorsabb, szelektív cache-eviction-t tesz lehetővé (§7.7).

## 7.7 Cache-kezelés

| Cache típus | Tartalom | Eviction-stratégia |
|---|---|---|
| Avatar cache | Kontaktok/csoportok profilképei | LRU (legrégebben használt eltávolítása), méretkorlát alapján |
| Thumbnail cache | Kép/videó előnézetek | LRU, méretkorlát alapján |
| Attachment cache | Letöltött, de nem "mentett" csatolmányok | Időalapú lejárat (pl. 30 nap), felhasználó explicit mentheti tartósra |

Fontos elvi kapcsolódás az EP2PC-001 §1.4 alapelvhez ("háttérben minden felesleges folyamat leáll") — a cache-eviction **nem** fut saját, önálló időzített háttérfolyamatként, hanem az alkalmazás előtérbe kerülésekor, illetve a Foreground Service ütemezett, ritka (nem polling-jellegű) karbantartási ablakában történik.

## 7.8 Backup és restore

- A teljes helyi adatbázis (üzenetek, kontaktok, csoport-metaadat) exportálható egy **külön, felhasználó által megadott jelszóval titkosított** archívumba — ez a jelszó **nem** azonos az Android Keystore-ban tárolt kulccsal, hogy a backup-fájl önmagában, az eredeti eszköztől függetlenül is visszaállítható legyen.
- A visszaállítás új eszközön a session-állapotokat (`sessions` tábla) is helyreállítja — ez viszont **nem** helyettesíti a kriptográfiai identitást: a multi-device koncepció (EP2PC-004 §4.3) különálló mechanizmus, a backup/restore inkább az "eszközcsere" forgatókönyvre való, nem a "több eszköz egyszerre" forgatókönyvre.
- A store-and-forward mechanizmus (EP2PC-003 §3.7) miatt egy visszaállított, régi backup-ból induló kliens elveszítheti a backup készítése és a visszaállítás közötti üzeneteket, ha azok TTL-je időközben lejárt a tároló peereken — ezt a korlátot a dokumentációban és a UI-ban is jelezni kell a felhasználó felé.

## 7.9 Adatmegőrzési és törlési politika

| Adat | Alapértelmezett megőrzés |
|---|---|
| Szöveges üzenetek | Amíg a felhasználó nem törli (nincs automatikus lejárat) |
| Csatolmány cache | 30 nap, ha nincs explicit mentve |
| Kimenő várólista (outbound_queue) | Amíg a kézbesítés nem sikerül, vagy amíg a felhasználó nem törli manuálisan a beszélgetést |
| Session-állapot (ratchet) | Amíg a kontakt aktív; kontakt törlésekor a session is törlődik |

Az EP2PC-005 §5.7-ben leírt "törlés mindenkinél" funkció a helyi adatbázis szintjén a `messages.deleted = 1` jelölést és a `body` mező felülírását/törlését jelenti — a sor maga (üresített tartalommal) megmaradhat, hogy a UI konzisztensen tudja jelezni "üzenet törölve" állapotot a beszélgetés idővonalán.

## 7.10 Fenyegetéselemzés — storage réteg

| Kockázat | Védelem |
|---|---|
| Eszköz elvesztése/ellopása | Teljes adatbázis- és fájlszintű titkosítás, kulcs hardver-biztonsági elemben |
| Backup-fájl illetéktelen kézbe kerülése | Külön, felhasználói jelszóval védett titkosítás, független az eszközkulcstól |
| Adatbázis-fájl közvetlen kiolvasása (root/jailbreak eszközön) | SQLCipher transzparens titkosítás — a fájl önmagában olvashatatlan a kulcs nélkül |
| Cache-fájlok (avatar, thumbnail) kevésbé védett tárolása | Ugyanazon titkosítási kulcs-hierarchia alá vonva, nem kerülnek nyílt formában lemezre |

---

# EP2PC-008 — Android Client

## 8.1 Célok és áttekintés

Ez a fejezet az EP2PC-002-ben lefektetett architektúra (Kotlin UI / Foreground Service / JNI / Rust Core) Android-specifikus megvalósítási részleteit írja le: a háttérműködés platform-szintű biztosítását, a JNI-határ pontos szerződését, a notifikáció-kezelést, az akkumulátor-optimalizáció platform-realitásait, és a felhasználói beállításokat.

Tervezési elv, közvetlenül az EP2PC-001 §1.4-ből: a Kotlin réteg **kizárólag megjelenítési és Android-platform-integrációs** felelősséggel bír. Minden üzleti logika, hálózati és kriptográfiai művelet a Rust Core-ban fut — ez nem csak a portolhatóság miatt fontos (EP2PC-002 §2.2), hanem azért is, mert a natív réteg finomabb kontrollt ad az energiafogyasztás és a szálkezelés felett, mint a Kotlin/JVM réteg önmagában.

## 8.2 Kotlin/Compose UI réteg

| Képernyő | Felelősség |
|---|---|
| Beszélgetéslista | Aktív 1:1 és csoport-beszélgetések áttekintése, utolsó üzenet előnézettel |
| Chat képernyő | Üzenetek megjelenítése, küldés, szerkesztés/törlés UI, csatolmány- és hangüzenet-felvétel |
| Kontaktok | Kontaktlista, QR-kód megjelenítés (saját PeerID) és beolvasás (EP2PC-003 §3.3) |
| Csoportkezelés | Tagok listája, admin-műveletek UI-ja (EP2PC-006 §6.3) |
| Beállítások | §8.7 szerint |

A Compose réteg **állapot nélküli** abban az értelemben, hogy minden perzisztens állapotot (üzenetek, session-ök, kulcsok) a Rust Core kezel — a UI a JNI-n keresztül kapott eseményfolyamra (Kotlin `Flow`) iratkozik fel, nem tart saját, párhuzamos state-forrást.

## 8.3 Foreground Service

- Az alkalmazás háttérműködése egyetlen, hosszú élettartamú **Foreground Service**-en keresztül valósul meg, minimális, folyamatos rendszerértesítéssel (ezt az Android platform megköveteli minden foreground service-hez).
- A service explicit **foreground service típussal** kerül deklarálásra a manifestben (a hálózati/adatszinkronizációs jellegnek megfelelő típus-kategóriában), az adott Android verzió által megkövetelt módon.
- A service élettartama a socket/event-loop élettartamával azonos (EP2PC-003 §3.8) — amíg fut, az epoll-alapú figyelés aktív; leállásakor (felhasználói kilépés vagy rendszer általi leállítás) a kliens offline-ként jelenik meg a partnerek felé, és a store-and-forward mechanizmus (EP2PC-003 §3.7) veszi át a szerepet.
- **Boot-time restart**: a felhasználó explicit engedélyével a service újraindul eszköz-újraindítás után is (`BOOT_COMPLETED` broadcast receiver), hogy a folyamatos elérhetőség ne szakadjon meg egy egyszerű újraindítástól sem.

```
Alkalmazás indítása
        │
        ▼
Foreground Service elindítása
        │
        ▼
Minimális, állandó notifikáció megjelenítése
        │
        ▼
JNI hívás: Rust Core inicializálása, event loop indítása
        │
        ▼
Service fut, amíg:
  - a felhasználó explicit ki nem lépteti, VAGY
  - a rendszer nem kényszeríti le (extrém memóriahiány esetén)
```

## 8.4 JNI interfész

A Kotlin ↔ Rust határ **aszinkron, esemény-vezérelt** modellt követ, nem szinkron, blokkoló hívásokat:

- **Kotlin → Rust irány**: parancs jellegű hívások (üzenet küldése, kontakt hozzáadása, csoport létrehozása) — ezek nem blokkolják a hívó szálat, a Rust oldal egy belső üzenetsoron dolgozza fel őket.
- **Rust → Kotlin irány**: regisztrált callback-interfészen keresztül érkező események (új üzenet érkezett, kézbesítési állapot változott, kapcsolat-állapot változott) — ezek a Kotlin oldalon egy `Flow`-ba kerülnek becsatornázásra, amire a Compose UI reaktívan feliratkozik.

```kotlin
// Kotlin oldali vázlat
external fun nativeSendMessage(conversationId: ByteArray, payload: ByteArray)
external fun nativeInit(callback: EP2PCEventCallback)

interface EP2PCEventCallback {
    fun onMessageReceived(envelope: ByteArray)
    fun onDeliveryStatusChanged(messageId: ByteArray, status: Int)
    fun onConnectionStateChanged(peerId: ByteArray, connected: Boolean)
}
```

- A Rust Core saját, dedikált natív szálon futtatja az async runtime-ot (event loop) — ez elkülönül az Android fő szálától és a Kotlin Coroutine-diszpécsertől, hogy a hálózati/kriptográfiai terhelés soha ne blokkolja a UI-t.
- A JNI-határon **kizárólag szerializált (protobuf) bájtsorozatok** mennek át — nyers kulcsanyag vagy Rust belső struktúra soha nem kerül át a Kotlin oldalra (EP2PC-004 §4.10-zel összhangban).

## 8.5 Notifikáció-kezelés

- Mivel a socket folyamatosan aktív (nincs szükség push-értesítésre, Firebase-re vagy más külső szolgáltatásra — EP2PC-003 §3.8), az új üzenet érkezésekor a Rust Core közvetlenül JNI-eseményt küld, amire a Kotlin réteg helyi Android-notifikációval reagál.
- **Alapértelmezett notifikáció-tartalom**: generikus szöveg (pl. "Új üzenet érkezett"), az üzenet valódi tartalma **nem** jelenik meg lezárt képernyőn — ez opcionálisan bekapcsolható a beállításokban, ha a felhasználó vállalja a kockázatot (lock-screen tartalom-szivárgás elkerülése, összhangban az EP2PC-001 §1.2 "zéró bizalom" elvével, itt kiterjesztve a fizikai eszköz-hozzáférésre is).
- A notifikációk beszélgetésenként csoportosítva jelennek meg (Android `NotificationChannel` / grouping API-k szerint).

## 8.6 Akkumulátor-optimalizáció — platform-specifikus realitás

Az EP2PC-003 §3.8-ban leírt eseményvezérelt (epoll), nulla-CPU nyugalmi állapot **szükséges, de nem elégséges** feltétel — az Android platform saját, gyártói és rendszerszintű energiakezelési mechanizmusai is figyelembe veendők:

| Mechanizmus | Hatás | Kezelés |
|---|---|---|
| Doze mode / App Standby | Rendszerszintű, a háttérfolyamatok hálózati hozzáférését és CPU-ütemezését korlátozhatja inaktivitás esetén | Foreground Service + explicit battery-optimization kizárás (a felhasználó által, ahogy a projekt kiinduló feltételezése is ez, EP2PC-001) kivonja az appot ezen korlátozások alól |
| Gyártói agresszív energiakezelés (pl. bizonyos Android-gyártók egyedi "battery saver" rétegei) | Egyes gyártói felületek a rendszer sztenderd mechanizmusain túl, saját listájuk alapján is leállíthatják a háttérfolyamatokat, akár a sztenderd kizárás megléte esetén is | UI-szintű, gyártóspecifikus útmutató a felhasználónak (a beállítások képernyőn, §8.7), amely segít megtalálni és kikapcsolni ezeket a réteges korlátozásokat |
| WorkManager periodikus feladatok | Nem ütemezett rendszeresen a fő üzenetfigyelő logikára — kizárólag ritka karbantartási feladatokra (pl. cache-eviction, EP2PC-007 §7.7) használt, nem a socket-figyelésre |
| Wakelock-ok | Nincs tartós, explicit CPU wakelock a socket-figyeléshez — az epoll-alapú modell (EP2PC-003 §3.8) natívan alacsony energiaigényű a Rust Core szintjén, a Foreground Service önmagában biztosítja a folyamat életben tartását |

## 8.7 Beállítások (Settings)

| Beállítás | Kapcsolódó fejezet |
|---|---|
| Bootstrap node-lista szerkesztése (saját node hozzáadása) | EP2PC-003 §3.5.4 |
| Olvasási visszaigazolás be/kikapcsolása | EP2PC-005 §5.8 |
| Keep-alive intervallum felülbírálása / adaptív mód | EP2PC-003 §3.8 |
| Notifikáció-tartalom megjelenítése lezárt képernyőn (be/ki) | §8.5 |
| Backup készítése / visszaállítás | EP2PC-007 §7.8 |
| Gyártói energiakezelési útmutató megnyitása | §8.6 |

## 8.8 Szükséges engedélyek

| Engedély | Cél |
|---|---|
| Kamera | QR-kód beolvasása kontakt hozzáadásához (EP2PC-003 §3.3) |
| Mikrofon | Hangüzenet felvétele (EP2PC-005 §5.10) |
| Értesítések (runtime permission) | Új üzenet notifikáció megjelenítése |
| Foreground service (deklarált típussal) | Folyamatos háttérműködés (§8.3) |
| Battery-optimization kizárás | A projekt alapfeltevése szerint a felhasználó ezt explicit engedélyezi (EP2PC-001 bevezető) |

## 8.9 Alkalmazás-életciklus állapotai

```
        ┌───────────────┐
        │   Foreground   │  (UI látható, aktív interakció)
        └───────┬────────┘
                │ háttérbe kerül
                ▼
        ┌───────────────┐
        │   Background   │  (csak Foreground Service fut,
        │   (Service)    │   UI nincs látható, socket aktív)
        └───────┬────────┘
                │ felhasználó kilépteti / rendszer leállítja
                ▼
        ┌───────────────┐
        │    Killed      │  (offline — store-and-forward
        │                │   veszi át a szerepet, EP2PC-003 §3.7)
        └───────┬────────┘
                │ eszköz-újraindítás (ha engedélyezett) vagy
                │ felhasználó manuális újranyitása
                ▼
        ┌───────────────┐
        │   Foreground   │
        └───────────────┘
```

## 8.10 Fenyegetéselemzés — Android platform-specifikus megjegyzések

| Kockázat | Megjegyzés / kezelés |
|---|---|
| Lock-screen notifikáció-tartalom szivárgás | Alapértelmezetten generikus notifikáció-szöveg (§8.5) |
| Gyártói battery-killer a sztenderd kizárás ellenére is leállítja a service-t | UI-szintű, gyártóspecifikus útmutató (§8.6, §8.7); ismert platform-korlát, nem teljes mértékben az alkalmazás oldaláról garantálható |
| JNI-határon átcsúszó nyers kulcsanyag | Kizárólag szerializált, nem-érzékeny payload megy át a határon (§8.4, EP2PC-004 §4.10) |
| Root-hozzáférésű eszközön a Kotlin/Java réteg memóriájának vizsgálata | A kritikus kulcsanyag a Rust Core natív memóriaterében és az Android Keystore-ban él, nem a Kotlin/JVM heap-en (EP2PC-004 §4.10, EP2PC-007 §7.4) |

---

# EP2PC-009 — Security & Testing

## 9.1 Célok és áttekintés

Ez a fejezet két dolgot fog össze: (1) az eddigi fejezetekben rétegenként rögzített fenyegetéselemzéseket egyetlen, konszolidált modellé rendezi, és (2) meghatározza azt a tesztelési stratégiát, amellyel a rendszer ezen garanciái ellenőrizhetők és fenntarthatók a fejlesztés teljes életciklusán át.

Alapelv: egy E2EE rendszernél a **teszteletlen kriptográfiai kód gyakorlatilag ér annyit, mint a nem létező kód** — egy finom hiba (pl. nonce-újrafelhasználás, hibás replay-ellenőrzés) észrevétlenül lerombolhatja az egész bizalmi modellt, miközben a funkcionális tesztek zöldek maradnak. Ezért a kriptográfiai réteg tesztelése kiemelt prioritású, külön szigorúbb elvárásokkal.

## 9.2 Konszolidált fenyegetésmodell

| Réteg | Fő fenyegetés | Elsődleges védelem | Részletek |
|---|---|---|---|
| Hálózat / bootstrap | Rosszindulatú bootstrap/relay node megpróbál tartalmat vagy identitást hamisítani | PeerID kriptográfiai ellenőrzése a Noise handshake-ben | EP2PC-003 §3.5.1–3.5.2 |
| NAT traversal | Man-in-the-middle a hole punching/relay közvetítésnél | A relay csak byte-folyamot lát, a titkosítás fölötte fut | EP2PC-003 §3.6 |
| Store-and-forward | Tároló peer metaadat-korrelációja, Sybil-pozicionálás, cenzúra | Rövid TTL, randomizált kiválasztás, redundáns tárolás | EP2PC-003 §3.7.3 |
| Kriptográfia | Kulcskompromittálódás, replay, MITM session-indításnál | Double Ratchet (forward secrecy + PCS), Ed25519-hitelesítés, nonce/replay-védelem | EP2PC-004 §4.11 |
| Üzenetprotokoll | Metaadat-szivárgás a fejlécből (`conversation_id`, `type`) | Tudatosan vállalt, minimalizált trade-off | EP2PC-005 §5.12 |
| Csoportprotokoll | Kizárt tag további hozzáférése, hamis admin-műveletek | Kötelező kulcsrotáció, aláírás-ellenőrzött vezérlő-üzenetek | EP2PC-006 §6.10 |
| Helyi tárolás | Eszköz elvesztése, root-hozzáférésű kiolvasás | SQLCipher + hardver-alapú kulcstárolás | EP2PC-007 §7.10 |
| Android platform | Lock-screen szivárgás, gyártói battery-killer megbízhatatlansága | Generikus notifikáció, felhasználói útmutatás | EP2PC-008 §8.10 |

## 9.3 Támadási felületek (attack surface)

| Felület | Kitettség |
|---|---|
| Nyilvánosan elérhető bootstrap/relay node-ok | Bármely internetezőtől érkező kapcsolódási kísérletnek ki vannak téve — ezeken a node-okon **nem** fut alkalmazás-üzleti logika, kizárólag libp2p protokollkezelés, ami csökkenti a támadási felületet |
| Bejövő libp2p stream-ek (bármely kliens oldalán) | Bármely peer küldhet tetszőleges, akár rosszindulatúan megformált protobuf-adatot — ez teszi kritikussá a §9.6 fuzzing-stratégiát |
| QR-kód beolvasás | Fizikai közelségű social engineering (hamis QR-kód becsempészése) — ez UX-szintű, nem kriptográfiai kockázat; a UI-nak egyértelműen meg kell jelenítenie az új kontakt PeerID-jét megerősítésre |
| Backup-fájl | Ha a felhasználó gyenge jelszót választ a backup titkosításához (EP2PC-007 §7.8), az offline brute-force kockázatot jelent — javasolt jelszó-erősség ellenőrzés a UI-ban |

## 9.4 Unit tesztelési stratégia

| Terület | Lefedettségi elvárás |
|---|---|
| Kriptográfiai primitívek (Ed25519, X25519, HKDF, AEAD) | Ismert válasz-vektoros tesztek (test vectors) a választott könyvtárak referencia-implementációi alapján |
| Double Ratchet állapotgép | Minden állapotátmenet (üzenetküldés, -fogadás, DH-ratchet lépés, skipped message key kezelés) izolált teszttel |
| Protobuf szerializáció/deszerializáció | Round-trip tesztek minden `Envelope` és payload típusra (EP2PC-005 §5.3–5.4) |
| Replay-védelmi logika | Determinisztikus tesztesetek: duplikált sorszám, régi ablakon kívüli üzenet, out-of-order érkezés |
| Csoport kulcsrotáció állapotgépe | Minden trigger (belépés, kilépés, eltávolítás) külön teszteset, epoch-konzisztencia ellenőrzéssel |
| SQLCipher séma-migrációk | Verzióváltás közbeni adatmegőrzés tesztelése |

## 9.5 Integrációs tesztelés

- **Multi-node szimulációs környezet**: több libp2p node indítása egyetlen teszt-futtatáson belül, szimulált hálózati körülményekkel (késleltetés, csomagvesztés, NAT-szimuláció), hogy a peer discovery (EP2PC-003 §3.4), a NAT traversal fallback-lánc (§3.6) és a store-and-forward (§3.7) végponttól végpontig tesztelhető legyen anélkül, hogy valódi mobilhálózatra lenne szükség.
- **Kulcsforgatókönyvek, amiket az integrációs tesztkészletnek kötelezően le kell fednie**:
  - Két kliens, mindkettő szigorú NAT mögött → hole punching, majd szükség esetén relay fallback sikeres lezárása
  - Egyik fél offline → store-and-forward → online állapotba kerülés → kézbesítés → tároló peer törli a példányt
  - Csoportból tag eltávolítása → kulcsrotáció → eltávolított tag ne tudja visszafejteni az azt követő üzeneteket
  - Bootstrap node ideiglenes elérhetetlensége → már csatlakozott kliensek továbbra is működnek egymás közt (EP2PC-003 §3.5.3 állítás ellenőrzése)

## 9.6 Fuzzing

Mivel bármely peer (akár rosszindulatú is) tetszőleges bájtsorozatot küldhet a hálózaton keresztül, a bejövő adatot feldolgozó komponensek **kötelezően fuzz-tesztelendők**:

| Komponens | Indoklás |
|---|---|
| Protobuf parser (`Envelope` és minden payload-típus) | Elsődleges támadási felület — minden bejövő hálózati adat ezen megy át elsőként |
| Double Ratchet header-feldolgozás | Hibás/manipulált ratchet-header nem vezethet crash-hez vagy állapot-inkonzisztenciához |
| DHT provider record feldolgozás | Rosszindulatú DHT-résztvevő hamis vagy deformált rekordokat is beilleszthet |
| Chunk-újraösszeállítási logika (EP2PC-005 §5.9) | Hiányos/duplikált/rosszul sorszámozott chunk-okra robusztusnak kell lennie |

Cél: egyetlen bejövő, nem-hitelesített adatcsomag se okozhasson crash-t, memóriaszivárgást vagy — ami a legsúlyosabb — kriptográfiai állapot-korrupciót.

## 9.7 Penetrációs tesztelés szempontjai

Ajánlott, hogy egy **független, harmadik fél** végezzen biztonsági auditot a rendszeren, mielőtt éles felhasználók kezébe kerülne, az alábbi fókuszterületekkel:

1. Kriptográfiai implementáció helyessége (nem csak a tervezés, hanem a tényleges kódmegvalósítás)
2. Session-kezelés és kulcstárolás az Android platformon (Keystore-integráció helyessége)
3. Hálózati protokoll-implementáció robusztussága rosszindulatú peerekkel szemben
4. Metaadat-szivárgás gyakorlati mértéke valós hálózati forgalom elemzésével

## 9.8 Teljesítmény- és energiatesztelés

Az EP2PC-001 §1.4-ben rögzített nem funkcionális követelmények mérhető ellenőrzése:

| Metrika | Mérési módszer |
|---|---|
| Nyugalmi CPU-használat | Profilozás (pl. Android Studio Profiler) hosszú idejű, forgalom nélküli háttérfutás alatt — elvárás: gyakorlatilag 0%, csak eseményvezérelt ébredés |
| Kapcsolatfelépítési idő | Mért időintervallum ismert peerhez (cache-elt cím) és új peerhez (DHT-lookup) egyaránt, §1.4 célértékeihez viszonyítva |
| Memóriahasználat | Nyugalmi és aktív (fájlátvitel alatti) RAM-fogyasztás mérése |
| Akkumulátor-fogyasztás valós eszközön | Többórás/napos háttérteszt valós Android eszközön, különböző hálózattípusok (WiFi/LTE/5G) mellett |

## 9.9 Ismert, tudatosan vállalt reziduális kockázatok

Az őszinteség kedvéért a dokumentáció explicit rögzíti azokat a korlátokat, amiket a rendszer tervezetten **nem** old meg teljes mértékben — ezek nem hiányosságok, hanem tudatos trade-offok, amiket a fejlesztőcsapatnak ismernie kell:

| Korlát | Miért vállalt trade-off |
|---|---|
| Metaadat (ki-kivel-mikor) részleges láthatósága a routing- és store-and-forward rétegben | A teljes metaadat-elrejtés (pl. teljes "sealed sender" + mix-network szintű anonimizálás) jelentősen növelné a komplexitást és a késleltetést — a jelen fázisban a tartalom titkossága az elsődleges cél, a metaadat-minimalizálás pedig folyamatos, iteratív fejlesztési irány (EP2PC-003 §3.7.3) |
| "Törlés mindenkinél" nem tud garanciát vállalni a már elolvasott/mentett tartalom eltávolítására | Minden E2EE rendszer velejáró korlátja (EP2PC-005 §5.7) |
| Gyártói agresszív battery-management megbízhatatlansága | Platform-szintű korlát, amit alkalmazás-oldalról csak részben lehet kezelni (EP2PC-008 §8.6, §8.10) |
| Régi backupból való visszaállítás elveszítheti a közbeni store-and-forward üzeneteket | A TTL-alapú tárolási politika (EP2PC-003 §3.7.4) velejárója (EP2PC-007 §7.8) |

---

# EP2PC-010 — Development Guide

## 10.1 Célok és áttekintés

Ez a záró fejezet a fejlesztői munkafolyamatot írja le: a repository-struktúrát, a kódolási konvenciókat, a build- és CI/CD-folyamatot, a verziózást, valamint a projekt hosszú távú útitervét (iOS-port, desktop-port, esetleges plugin-rendszer). Célja, hogy egy új fejlesztő — a korábbi kilenc fejezet ismeretében — önállóan be tudjon kapcsolódni a fejlesztésbe.

## 10.2 Repository- és mappastruktúra

Javasolt **monorepo** elrendezés, mivel a Rust Core több kliens (Android, később iOS/desktop) között is megosztott:

```
ep2pc/
├── core/                    # Rust Core (platformfüggetlen)
│   ├── src/
│   │   ├── network/         # libp2p host, DHT, NAT traversal (EP2PC-003)
│   │   ├── crypto/          # Ed25519, X25519, Double Ratchet (EP2PC-004)
│   │   ├── messaging/       # Envelope, protobuf típusok (EP2PC-005)
│   │   ├── group/           # Csoportprotokoll (EP2PC-006)
│   │   ├── storage/         # SQLCipher réteg (EP2PC-007)
│   │   └── ffi/             # JNI / jövőbeli C-FFI határ
│   └── Cargo.toml
├── android/                 # Kotlin/Compose kliens (EP2PC-008)
│   ├── app/
│   └── build.gradle.kts
├── proto/                   # Megosztott .proto sémafájlok (EP2PC-005, EP2PC-006)
├── docs/                    # Ez a dokumentációs csomag (EP2PC-001…010)
└── tools/                   # Fejlesztői segédeszközök (pl. multi-node teszt-szimulátor, EP2PC-009 §9.5)
```

A `core/` modul **semmilyen** Android-specifikus függőséget nem tartalmazhat — ez a portolhatóság előfeltétele (EP2PC-002 §2.2, §10.8–10.9).

## 10.3 Kódolási konvenciók

| Nyelv | Formázó / linter | Megjegyzés |
|---|---|---|
| Rust | `rustfmt` + `clippy` (figyelmeztetés-mentes build elvárás) | A `crypto/` modulban extra szigor: minden publikus függvény dokumentált, unsafe blokk csak indoklással |
| Kotlin | `ktlint` | Compose-specifikus konvenciók (state hoisting, egyirányú adatfolyam) |
| Protobuf | Egységes névtér-konvenció (`ep2pc.<modul>.v<verzió>`, EP2PC-005 §5.2) | Minden mezőszám-változtatás csak `reserved` jelöléssel, visszafelé kompatibilis módon |
| Commit üzenetek | Konvencionális commit formátum (`feat:`, `fix:`, `docs:` stb.) | Megkönnyíti az automatikus changelog-generálást |

## 10.4 Build rendszer

- **Rust Core**: Cargo workspace, több crate-re bontva a §10.2 mappastruktúra szerint.
- **Android cross-compilation**: a Rust Core Android-célarchitektúrákra (arm64-v8a elsődlegesen, a piaci lefedettség szerint kiegészítve) fordítva, natív `.so` könyvtárként ágyazódik be a Gradle build-be.
- **Gradle**: a Kotlin/Compose alkalmazás build-je, amely a natív könyvtárat és a JNI-kötéseket (EP2PC-008 §8.4) integrálja.

## 10.5 CI/CD pipeline

```
Commit / Pull Request
        │
        ▼
1. Lint (rustfmt/clippy, ktlint)
        │
        ▼
2. Unit tesztek (EP2PC-009 §9.4) — Rust és Kotlin oldalon egyaránt
        │
        ▼
3. Integrációs tesztek (multi-node szimuláció, EP2PC-009 §9.5)
        │
        ▼
4. Rövid, gyorsított fuzzing-futtatás (EP2PC-009 §9.6) —
   teljes fuzzing-kampány külön, ütemezett (nem minden commit-nál)
        │
        ▼
5. Android build (debug APK) — automatikus telepíthetőségi ellenőrzés
        │
        ▼
Zöld pipeline → merge engedélyezett
```

A teljes (hosszabb futású) fuzzing-kampány és a §9.7 szerinti penetrációs tesztelés **nem** a minden-commit-os CI-ban fut, hanem ütemezetten (pl. release-ek előtt), erőforrás-megfontolásból.

## 10.6 Verziózás és release

- A **Rust Core** szemantikus verziózást követ (`major.minor.patch`) — a protokoll-szintű, nem visszafelé kompatibilis változtatások (pl. `Envelope` séma törő módosítása) major-verzió emelést igényelnek.
- Az **Android alkalmazás** saját, a Core-verziótól független build-számozást használhat, de a `CHANGELOG.md`-ben mindig rögzíteni kell, mely Core-verzióval lett összeállítva.
- Minden release előtt kötelező checklist: unit + integrációs tesztek zöldek, teljesítmény-mérés (EP2PC-009 §9.8) a célértékeken belül, ismert reziduális kockázatok (EP2PC-009 §9.9) átvizsgálva és a release-jegyzetekben szükség esetén megemlítve.

## 10.7 Fejlesztési roadmap (fázisok)

| Fázis | Tartalom |
|---|---|
| **1. fázis — Core hálózati alap** | Transport, Noise, Kademlia DHT, bootstrap (EP2PC-003), alap identitás (EP2PC-004 §4.3) |
| **2. fázis — 1:1 titkosított üzenetküldés** | Teljes Double Ratchet (EP2PC-004), szöveges üzenetek (EP2PC-005 §5.5), helyi tárolás (EP2PC-007) |
| **3. fázis — Offline-first** | Store-and-forward (EP2PC-003 §3.7), retry-logika (EP2PC-005 §5.11) |
| **4. fázis — Csatolmányok** | Chunkolás, kép/fájl küldés (EP2PC-005 §5.9) |
| **5. fázis — Csoportok** | Teljes csoportprotokoll (EP2PC-006) |
| **6. fázis — Hangüzenetek** | Opus-integráció (EP2PC-005 §5.10) |
| **7. fázis — Megerősítés** | Biztonsági audit (EP2PC-009 §9.7), teljesítmény-finomhangolás, gyártói battery-management kompatibilitás (EP2PC-008 §8.6) |
| **8. fázis — Multi-device** | Eszköz-alkulcsok (EP2PC-004 §4.3), több eszköz szinkronizálása egy identitáshoz |
| **9. fázis — iOS port** | §10.8 szerint |
| **10. fázis — Desktop port** | §10.9 szerint |

Az egyes fázisok nem feltétlenül szigorúan szekvenciálisak — egy kis fejlesztőcsapat párhuzamosíthatja a 4–6. fázisokat, amint a Core hálózati és kriptográfiai alapja (1–3. fázis) stabil.

## 10.8 iOS port követelményei

- A `core/` Rust modul **változtatás nélkül** újrafelhasználható — ez volt a platformfüggetlen Core melletti eredeti döntés indoka (EP2PC-002 §2.2).
- A JNI-t (EP2PC-008 §8.4) egy C-kompatibilis FFI-határ váltja fel iOS-en (pl. `uniffi`-szerű kötésgenerátorral, hogy a Swift oldali kötések automatikusan, séma-vezérelten generálódjanak a Rust API-ból, csökkentve a kézi karbantartási terhet).
- A Swift/SwiftUI kliens ugyanazt a réteg-elválasztási elvet követi, mint a Kotlin/Compose (EP2PC-008 §8.2): kizárólag megjelenítés és platform-integráció, üzleti logika nélkül.
- Platform-specifikus háttérműködési kihívás: az iOS energiakezelési és háttérfutási modellje jelentősen eltér az Androidétól (nincs közvetlen megfelelője a Foreground Service-nek) — ez a fázis kezdetén külön, iOS-specifikus tervezési vizsgálatot igényel, hasonló mélységben, mint az EP2PC-008.

## 10.9 Desktop port követelményei

- Ugyanaz a Rust Core, natív desktop UI réteggel (a technológiaválasztás — natív toolkit vagy egy könnyű, webalapú shell — külön döntési pont, ami nem befolyásolja a Core-ot).
- Multi-device forgatókönyv elsődleges haszonélvezője: a desktop kliens jellemzően nem "elsődleges" eszköz, hanem az EP2PC-004 §4.3 szerinti eszköz-alkulcs modell egyik résztvevője.

## 10.10 Jövőbeli plugin-rendszer (koncepcionális vázlat)

Ez a terület a jelen dokumentáció-verzióban még nyitott, kizárólag irányjelzésként rögzítve: hosszú távon elképzelhető egy korlátozott, jogosultság-alapú kiterjesztési pont (pl. egyedi üzenettípusok, EP2PC-005 §5.3 típuskód-tartomány fenntartásával harmadik féltől származó bővítmények számára) — ennek részletes tervezése és biztonsági modellje **külön, jövőbeli specifikáció** tárgya lesz, nem része a jelen v0.1 dokumentációs csomagnak.

---

# A dokumentációs csomag lezárása (v0.1)

Ezzel a tíz fejezet (EP2PC-001 – EP2PC-010) lefedi a teljes, közösen megtervezett rendszert: a célkitűzésektől és követelményektől kezdve, a hálózati és kriptográfiai alapokon át, az üzenet- és csoportprotokollon, a helyi tároláson és az Android-kliensen keresztül, egészen a biztonsági/tesztelési stratégiáig és a fejlesztési útitervig.

**A dokumentum jellege továbbra is "élő".** Amint a fejlesztés megkezdődik és részletkérdések merülnek fel (pl. konkrét könyvtárválasztás egy adott primitívhez, egy állapotgép finomítása éles teszt tapasztalatok alapján), az érintett fejezet frissíthető — a moduláris, önállóan verziózható felépítés (ahogy az eredeti tervezési beszélgetésben is elhangzott) pontosan ezt a rugalmasságot szolgálja, anélkül hogy a többi fejezetet újra kellene írni.

**Javasolt következő lépés:** a dokumentum átadása a fejlesztőcsapatnak áttekintésre, különös figyelemmel az EP2PC-004 (Cryptography) és EP2PC-009 (Security & Testing) fejezetekre — ezek azok a részek, ahol egy független szakértői átnézés a legnagyobb értéket adja, mielőtt a tényleges implementáció megkezdődne.