import mysql.connector

#connect to local db
db = mysql.connector.connect(host="localhost", user="#", passwd="#",database="#")

cursor=db.cursor()

readFile=open("./classCode/demoData/uploadEmail.txt","r")
email=readFile.read()
readFile.close()

readFile=open("./classCode/demoData/uploadPublicKey.txt","r")
publicKey=readFile.read()
readFile.close()

readFile=open("./classCode/demoData/uploadPrivateKey.txt","r")
privateKey=readFile.read()
readFile.close()

ask="INSERT INTO keyStore VALUES (%s,%s,%s)"
vals=(email, publicKey, privateKey)

cursor.execute(ask,vals);

db.commit()