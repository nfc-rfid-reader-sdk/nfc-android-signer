  The XML Security project is an implementation of
  security related XML standards. Currently, it includes
  implementations of W3C recommendations "Canonical XML",
  "Canonical XML 1.1", "XML Signature Syntax and Processing",
  and "XML Encryption Syntax and Processing".

  Basically, this means that you can use this software
  for creating and verifying digital signatures which
  are expressed in XML and sign both XML and/or arbitrary
  contents. You can use the standard JSR 105 (Java XML
  Digital Signature) API or the non-standard Apache XMLSec API.

  You can also use the library to encrypt and decrypt
  portions of XML documents. Only the non-standard Apache
  XMLSec API is supported, as the JSR 106 (Java XML Digital Encryption) 
  API is still in development.

For more information about the XML Security project, please go to
http://santuario.apache.org/

For more information about XML Signature, go to
http://www.w3.org/Signature/

For more information about XML Encryption, go to
http://www.w3.org/Encryption/


PREPRAVLJANJE JAR DISTRIBUCIONOG FAJLA ZA ANDROID:
Bez problema se mogu importovati verzije starije od 2.0.0 (poslednja èiju sam prepravku uradio je 1.5.8).
Jednostavno se "xmlsec-1.5.8.jar" (xmlsec-x.y.z.jar) otvori nekim arhiver fajl menadžerom (npr. 7-zip-ovim) i obriše se "javax" folder u prvom nivou arhive. 
Ubaci se taj JAR fajl u "dependencies" projekta (ja ih preimenujem u xmlsec-x.y.z-android.jar) i to je sve.
