# Unpacking-of-a-IcedID-07.2021

After opening a malicious document(IcedID), a malicious executable library is usually loaded onto the victim's system, which has a packed payload.This script is written to help the analyst unpack the executable library for further research.

Usage:

python Unpacker-IcediD.py incoming file(IcediD.dll)   open payload

Example:

python Unpacker-IcediD.py C:\IcediD.dll_  C:\PlayLoadIcediD.dll_
  
 

The script successfully unpacks the following files.
f34fa6b71742ce62bf83ff444bf1542af65bed81af43f97566a2efdd6cf6f939
33cc3816f98fa22354559711326a5ce1352d819c180be4328a72618d20a78632
e5c30832f0cd52c7b10e933e441041af28840449d733e794930f9f636432f4c0
7dea4a06a8d44a0f6bac2aed3751066f0fb40f148868585d4f5d9a6e481818b4
    
At the beginning of the script, you can see which file it is intended for.

https://inquest.net/blog/2021/07/19/icedid-070721
