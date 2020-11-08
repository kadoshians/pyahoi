# pyahoi für KÂDO
![Logo](images/logo.png "Logo")

Dieses Projekt ist das Backend für die Idee KÂDO by Kadoshians.
Die Idee ist im Rahmen des [Symbiotion 2020 Hackathons](https://symbioticon.de/ "Symbiotion 2020 Hackathons") entstanden und ist ein modernes Konzept der klassischen Stempelkarte.
Nutzer sammeln Stempel auf KÂDOS (japanisch für Karten), die im Wallet auf den Handys gepsiechert werden.
Dieses Projekt baut auf den APIs von [AHOI](https://www.starfinanz-ahoi.de/de/ "AHOI") und [your pass](https://yourpass.eu "your pass") auf.
Die Stempel können durch Abscannen des QR Codes im Geschäft oder durch Analyse der Zahlungen mit EC-Karte oder Mastercard gesammelt werden.

Der Prozess für das Sammeln aus Nutzersicht umfasst folgende Schritte:
1. Nutzer verknüpft sein Bankkonto mit der pyahoi für KÂDO
2. Das Backend ruft täglich die Transaktionen ab und erkennt, wenn Läden mit KÂDOS besucht wurden
3. Nutzer erhalten eine Notification über ihren gesammelten Stempel wenn die Transaktion erkannt wurde
4. Nutzer freut sich :-)

## KÂDO in dem Wallet
Der Nutzer kann sein KÂDO direkt im Wallet nutzen und von dem Händler scannen lassen.
Hierfür ist auf jedem KÂDO ein QR-Code angezeigt, mit der ein Händler den Besuch uns weitergeben kann.
![KÂDO](images/kado.png "KÂDO")

## Notification bei Kartenzahlung
Noch einfacher wird das Sammeln mit KÂDO, wenn der Nutzer das eigene Bankkonto verknüpft.
Dann bekommen Nutzer direkt eine Notification, sobald ein Umsatz bei dem Händler erkannt wurde.
Bei dem Einkauf muss nichts gescannt werden und niemand kann den Stempel vergessen.
![Notification](images/notification.png "Notification")

## Verwendung der AHOI Api
Für die Analyse der Transaktionen auf dem Konto nutzen wir die *AHOI API*.
Die einzenen Umsätze werden mit dem KÂDO des Geschäfts verbunden, so dass jeder Einkauf auch berücksichtigt wird.
Auf Basis der bisherigen Transaktionen können weitere KÂDOS von Händlern, die man gerne besucht, empfohlen werden.