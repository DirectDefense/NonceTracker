Nonce Tracker
BurpExtender.java
ABlakemore
http://www.directdefense.com

Introduction
============

A Burp extender module that tracks and updates nonce values per a specific application action.

Usage
=====

 - Download the latest Burp API package from http://portswigger.net/burp/extender/
 - Modify regexes to match your particular nonce location and name.
  - Don't forget to change split and replace regexes
  - If you do not need to deal with directory rewriting, modify or remove rqPage
 - Compile Jar (http://blog.portswigger.net/2009/04/using-burp-extender.html)
 - Load Jar into Burp Extender
 - You can always at some output to ensure your code is working or daisy chain proxies to verify rewrite is working.
 - Start Testing
 

COPYRIGHT
=========

BurpExtender.java
Created by A. Blakemore
Copyright (C) 2013 DirectDefense, Inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
