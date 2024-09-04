#For RootCA:
cd RootCA/

openssl req -new -config CSRConfRootCA.cnf -key root-private-key.pem -out RootCA.csr #Generate RootCA CSR

openssl x509 -req -days 365 -in RootCA.csr -signkey root-private-key.pem -out rootCA.crt -extfile extensionsRootCA.txt #Generate RootCA Self-Signed Certificate


#For InterCA:
cd ../InterCA/

openssl req -new -config CSRConfInterCA.cnf -key Inter-private-key.pem -out InterCA.csr

openssl x509 -req -in InterCA.csr -CA ../RootCA/rootCA.crt -extfile extensionsInterCA.txt -CAkey ../RootCA/root-private-key.pem -CAcreateserial -out InterCA.crt -days 365 -sha256

#For Bob:
cd ../Bob/

openssl req -new -config CSRConfBob.cnf -key Bob.pem -out Bob.csr

openssl x509 -req -in Bob.csr -CA ../InterCA/InterCA.crt -extfile extensionsBob.txt -CAkey ../InterCA/Inter-private-key.pem -CAcreateserial -out Bob.crt -days 365 -sha256


#For Alice:
cd ../Alice/

openssl req -new -config CSRConfAlice.cnf -key Alice.pem -out Alice.csr

openssl x509 -req -in Alice.csr -CA ../InterCA/InterCA.crt -extfile extensionsAlice.txt -CAkey ../InterCA/Inter-private-key.pem -CAcreateserial -out Alice.crt -days 365 -sha256
