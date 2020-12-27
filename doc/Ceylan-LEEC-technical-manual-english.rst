
.. _Top:


.. title:: Welcome to the Ceylan-LEEC 0.5.0 documentation

.. comment stylesheet specified through GNUmakefile


.. role:: raw-html(raw)
   :format: html

.. role:: raw-latex(raw)
   :format: latex

.. comment Would appear too late, can only be an be used only in preamble:
.. comment :raw-latex:`\usepackage{graphicx}`
.. comment As a result, in this document at least a '.. figure:: XXXX' must
.. exist, otherwise: 'Undefined control sequence \includegraphics.'.


:raw-html:`<a name="leec_top"></a>`

:raw-html:`<div class="banner"><p><em>LEEC 0.6 documentation</em> <a href="http://leec.esperide.org">browse latest</a> <a href="https://olivier-boudeville.github.io/Ceylan-LEEC/leec.html">browse mirror</a> <a href="leec.pdf">get PDF</a> <a href="#leec_top">go to top</a> <a href="#leec_bottom">go to bottom</a> <a href="mailto:about(dash)leec(at)esperide(dot)com?subject=[Ceylan-LEEC%200.6]%20Remark">email us</a></p></div>`



:raw-html:`<center><img src="leec-title.png" width="50%"></img></center>`
:raw-latex:`\includegraphics[scale=0.40]{leec-title.png}`




--------------------------------------
LEEC: Let's Encrypt Erlang with Ceylan
--------------------------------------


:Organisation: Copyright (C) 2020-2021 Olivier Boudeville
:Contact: about (dash) leec (at) esperide (dot) com
:Creation date: Wednesday, November 11, 2020
:Lastly updated: Sunday, December 27, 2020
:Dedication: Users and maintainers of the ``LEEC`` library, version 0.6.
:Abstract:

	The role of the ``LEEC`` library is to interact from Erlang/OTP with Let's Encrypt servers, mostly in order to generate X.509 certificates.


.. meta::
   :keywords: LEEC, X509, certificate, SSL, https, Erlang


The latest version of this documentation is to be found at the `official LEEC website <http://leec.esperide.org>`_ (``http://leec.esperide.org``).

:raw-html:`This LEEC documentation is also available in the PDF format (see <a href="leec.pdf">leec.pdf</a>), and mirrored <a href="http://olivier-boudeville.github.io/Ceylan-LEEC/leec.html">here</a>.`

:raw-latex:`The documentation is also mirrored \href{https://olivier-boudeville.github.io/Ceylan-LEEC/leec.html}{here}.`



:raw-latex:`\pagebreak`



.. _`table of contents`:


.. contents:: Table of Contents
  :depth: 3


:raw-latex:`\pagebreak`


Overview
========

The online documentation for LEEC is currently available `here <https://github.com/Olivier-Boudeville/letsencrypt-erlang>`_.



Getting Information about the Generated Certificates
====================================================

If using LEEC to generate a certificate for a ``baz.foobar.org`` host, the following three files shall be obtained from the Let's Encrypt ACME server:

- ``baz.foobar.org.csr``: the PEM certificate request, sent to the ACME server (~980 bytes)
- ``baz.foobar.org.key``: the TLS private key regular file, kept on the server (~1675 bytes)
- ``baz.foobar.org.crt``: the PEM certificate itself of interest (~3450 bytes), to be used by the webserver


To get information about this certificate::

 $ openssl x509 -in baz.foobar.org.crt -text -noout

 Certificate:
	Data:
		Version: 3 (0x2)
		Serial Number:
			04:34:17:fd:ee:9b:bd:6b:c2:02:b1:c0:84:62:ed:a6:88:5c
		Signature Algorithm: sha256WithRSAEncryption
		Issuer: C = US, O = Let's Encrypt, CN = R3
		Validity
			Not Before: Dec 27 08:21:38 2020 GMT
			Not After : Mar 27 08:21:38 2021 GMT
		Subject: CN = baz.foobar.org
		Subject Public Key Info:
			Public Key Algorithm: rsaEncryption
				RSA Public-Key: (2048 bit)
 [...]



Support
=======

Bugs, questions, remarks, patches, requests for enhancements, etc. are to be sent through the `project interface <https://github.com/Olivier-Boudeville/letsencrypt-erlang>`_, or directly at the email address mentioned at the beginning of this document.



Please React!
=============

If you have information more detailed or more recent than those presented in this document, if you noticed errors, neglects or points insufficiently discussed, drop us a line! (for that, follow the Support_ guidelines).


Ending Word
===========

Have fun with LEEC!

.. comment Mostly added to ensure there is at least one figure directive,
.. otherwise the LateX graphic support will not be included:

.. figure:: leec-title.png
   :alt: LEEC logo
   :width: 35%
   :align: center

:raw-html:`<a name="leec_bottom"></a>`
