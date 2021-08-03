#f34fa6b71742ce62bf83ff444bf1542af65bed81af43f97566a2efdd6cf6f939
def Searchciphertext (dump):
  for i in range (len(dump)):
    comsize = len(dump)
    symb = dump[i]
    if symb == 0x34:
      symb = dump[i+1]
      if symb == 0x6C:
        symb = dump[i+2]
        if symb == 0x35:
          symb = dump[i+3]
          if symb == 0x72:
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

def decrypt(offset, size, dump, result):
  cont = 0xE4
  r = 0
  i = 0
  loop = size - offset - 1
  while i < loop:
    n1 = dump[i] - 0x2A  
    n2 = dump[i+1] - 0x63
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
  file = open("malware.dll_","rb")
  dump = bytearray(file.read())
  offset,size = Searchciphertext(dump)

  dump = file.seek(offset,0)
  
  dump = bytearray(file.read(size-offset))
  
  result = bytearray(15000)
  opendata = decrypt(offset, size, dump, result)
  
  new = open("unpack.dll_","wb")
  new.write(opendata)
  new.close()
  file.close()
  
  
  
  
  
  
  
  
  
  
