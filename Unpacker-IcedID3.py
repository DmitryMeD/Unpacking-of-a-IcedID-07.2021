#To unpack  e5c30832f0cd52c7b10e933e441041af28840449d733e794930f9f636432f4c0

import sys


def Searchciphertext (dump):
  
  for i in range (len(dump)):
    comsize = len(dump)
    symb = dump[i]
    if symb == 0x34:
      symb = dump[i+1]
      if symb == 0x71:
        symb = dump[i+2]
        if symb == 0x33:
          symb = dump[i+3]
          if symb == 0x77:
            offset = i
            print("Success ciphertext ICEDID 07.2021 was found")
			
  i = offset

  while i< 100000:
    if dump[i] == 0:
      symb = dump[i+1]
      if symb == 0:
        symb = dump[i+2]
        if symb == 0:
          symb = dump[i+3]
          if symb == 0:
            size = i
            break
    i += 1
  
  return offset, size
  
  
def openfile (s):
  sys.stderr.write(s + "\n")
  sys.stderr.write("Usage: %s <infile> <outfile>\n" % sys.argv[0])
  sys.exit(1)  

def decrypt(offset, size, dump, result):
  cont = 0xB4
  r = 0
  i = 0
  loop = size - offset - 1
  while i < loop:
    n1 = dump[i] - 0x25
    n2 = dump[i+1] - 0x68
    n1 = n1 << 4
    n3 = n1 | n2
    n3 = cont ^ n3
    cont = cont + 1
    if cont == 0x100:
        cont = 0
    result[r] += n3
    r += 1
    i += 2
  print("Decryption was successful")
  return(result)
  
 
if __name__ == '__main__':
  
  if len(sys.argv) != 3:
    openfile("invalid argument count")
  outfile = sys.argv.pop()
  infile  = sys.argv.pop()
  
  
  file = open(infile,"rb")
  dump = bytearray(file.read())
  offset , size = Searchciphertext(dump)
  dump = file.seek(offset,0)
  
  dump = bytearray(file.read(size-offset))
  
  result = bytearray(15000)
  opendata = decrypt(offset, size, dump, result)
  
  new = open(outfile,"wb")
  new.write(opendata)
  new.close()
  file.close()
  
  
  
  
  
  
  
  
  
  
