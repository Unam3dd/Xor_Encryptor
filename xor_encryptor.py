#!/usr/bin/python2
#-*- coding:utf-8 -*-


import os
import sys
import base64
from itertools import izip, cycle
import zlib

banner = '''
\033[32m                                   
                  :                
                 t#,               
                ;##W.   j.         
               :#L:WE   EW,        
  :KW,      L .KG  ,#D  E##j       
   ,#W:   ,KG EE    ;#f E###D.     
    ;#W. jWi f#.     t#iE#jG#W;    
     i#KED.  :#G     GK E#t t##f   
      L#W.    ;#L   LW. E#t  :K#E: 
    .GKj#K.    t#f f#:  E#KDDDD###i
   iWf  i#K.    f#D#;   E#f,t#Wi,,,
  LK:    t#E     G#t    E#t  ;#W:  
  i       tDj     t     DWi   ,KK: 
                                   
                                   
            Created By \033[31mUnam3dd\033[32m

            Github : \033[31mUnam3dd\033[00m

            \033[35mXor Encryptor/Decryptor With Base64
\033[00m
'''

def python_required():
    if sys.version[0] =="3":
        sys.exit("[*] Python2.7 Required For This Script !")


var_xor_decrypt = '''
def xor_crypt(data, key, encode=False, decode=False):
    if decode:
        data = base64.decodestring(data)
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    if encode:
        return base64.encodestring(xored).strip()
    return xored
'''

def xor_crypt(data, key, encode=False, decode=False):
    if decode:
        data = base64.decodestring(data)
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    if encode:
        return base64.encodestring(xored).strip()
    return xored


def string_encode(string,xor_key):
    try:
        print("\033[32m[\033[34m+\033[32m] Raw => %s\033[00m\n" % (string))
        xsenc = xor_crypt(string,xor_key,encode=True)
        print("\033[32m[\033[34m+\033[32m] Encrypted => %s\033[00m\n" % (xsenc))
        print("\033[32m[\033[34m+\033[32m] Using Xor Key => %s\033[00m\n" % (xor_key))
    except:
        print("\033[31m[!] Error Encrypt String\033[00m\n")


def encrypt_file(filename,xor_key,output_file):
    try:
        check_path = os.path.exists(filename)
        if check_path ==True:
            print("\033[32m[\033[34m+\033[32m] %s Found !\033[00m\n" % (filename))
            of=open(output_file,"w")
            with open(filename,"r") as f:
                content = f.read()
                xsenc = xor_crypt(content,xor_key,encode=True)
                of.write(xsenc)
                
            of.close()
            print("\033[32m[\033[34m+\033[32m] %s File Encrypted ! Save As %s\033[00m\n" % (filename,output_file))
            print("\033[32m[\033[34m+\033[32m] Using Xor Key : %s\033[00m\n" % (xor_key))
                
        else:
            print("\033[32m[\033[34m+\033[32m] %s Not Found !\033[00m\n")
    
    except:
        print("\033[31m[!] Error Encrypt File!\033[00m\n")


def decrypt_file(filename,xor_key,output_file):
    try:
        check_path = os.path.exists(filename)
        if check_path ==True:
            print("\033[32m[\033[34m+\033[32m] %s Found !\033[00m\n" % (filename))
            of=open(output_file,"w")
            with open(filename,"r") as f:
                content = f.read()
                xdenc = xor_crypt(content,xor_key,decode=True)
                of.write(xdenc)
            
            of.close()
            print("\033[32m[\033[34m+\033[32m] %s File Decrypted ! Save As  %s\033[00m\n" % (filename,output_file))
            print("\033[32m[\033[34m+\033[32m] Using Xor Key : %s" % (xor_key))

    except:
        print("\033[31m[!] Error Decrypt File !\n")

def string_decode(string,xor_key):
    try:
        print("\033[32m[\033[34m+\033[32m] Encrypted => %s\033[00m\n" % (string))
        xsdenc = xor_crypt(string,xor_key,decode=True)
        print("\033[32m[\033[34m+\033[32m] Decrypted => %s\033[00m\n" % (xsdenc))
    except:
        print("\033[31m[!] Error Decrypt String\033[00m\n")

if __name__ == '__main__':
    python_required()
    print(banner)
    try:
        
        if len(sys.argv)>=4:
            print("usage : %s --help" % (sys.argv[0]))
            print("        %s template_encrypt_file <filename> <xor_key> <new_template_name>" % (sys.argv[0]))
            print("        %s encrypt_file <filename> <xor_key> <new_template>" % (sys.argv[0]))
            print("        %s decrypt_file <filename> <xor_key> <outputfile>" % (sys.argv[0]))
            print("        %s string_encrypt <string> <xor_key>" % (sys.argv[0]))
            print("        %s string_decrypt <string> <xor_key>" % (sys.argv[0]))
        
        if sys.argv[1] =="string_encrypt":
            string_encode(sys.argv[2],sys.argv[3])
        
        elif sys.argv[1] =="string_decrypt":
            string_decode(sys.argv[2],sys.argv[3])
        
        elif sys.argv[1] =="encrypt_file":
            encrypt_file(sys.argv[2],sys.argv[3],sys.argv[4])
        
        elif sys.argv[1] =="decrypt_file":
            decrypt_file(sys.argv[2],sys.argv[3],sys.argv[4])
        
        elif sys.argv[1] =="template_encrypt_file":
            f=open(sys.argv[2],"r")
            content = f.read()
            f.close()
            xenc = xor_crypt(content,sys.argv[3],encode=True)
            f=open(sys.argv[4],"w")
            f.write("#!/usr/bin/python2\n")
            f.write("#-*- coding:utf-8 -*-\n")
            f.write("\n")
            f.write("import base64\n")
            f.write("from itertools import izip, cycle\n")
            #f.write("import zlib\n")
            f.write("\n")
            f.write(var_xor_decrypt+"\n")
            f.write("\n")
            f.write('payload = "%s"\n' % (xenc))
            f.write("\n")
            #f.write('d = zlib.decompress(payload)\n')
            f.write('exec(xor_crypt(payload,"%s",decode=True))\n' % (sys.argv[3]))
            f.close()
            print("\033[32m[\033[34m+\033[32m] Payload Created Save As : %s\n" % (sys.argv[4]))
            print("\033[32m[\033[34m+\033[32m] Using Xor Key : %s\n" % (sys.argv[4]))

        else:
            print("\033[31m[!] Error Options\033[00m\n")
            print("\n")
    
    except IndexError:
        print("\033[32musage : %s" % (sys.argv[0]))
        print("        %s encrypt_file_template <filename> <xor_key> <new_template_name>" % (sys.argv[0]))
        print("        %s encrypt_file <filename> <xor_key> <new_template>" % (sys.argv[0]))
        print("        %s decrypt_file <filename> <xor_key> <outputfile>" % (sys.argv[0]))
        print("        %s string_encrypt <string> <xor_key>" % (sys.argv[0]))
        print("        %s string_decrypt <string> <xor_key>\033[00m" % (sys.argv[0]))
        print("\n")
        print("\033[31m[!] Error Options\033[00m\n")