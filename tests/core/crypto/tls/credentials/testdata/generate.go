// Local synthetic fixtures only; keys are public test material, never identities.
package main
import("crypto/rand";"crypto/rsa";"crypto/x509";"crypto/x509/pkix";"encoding/pem";"math/big";"os";"path/filepath";"time")
func save(dir,name string,b []byte){if err:=os.WriteFile(filepath.Join(dir,name),b,0600);err!=nil{panic(err)}}
func main(){dir:=os.Args[1];for _,bits:=range []int{1024,2048,4096}{
 key,e:=rsa.GenerateKey(rand.Reader,bits);if e!=nil{panic(e)}
 prefix:=big.NewInt(int64(bits)).String()
 der,e:=x509.MarshalPKCS8PrivateKey(key);if e!=nil{panic(e)}
 save(dir,"rsa"+prefix+".pem",pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der}))
 if bits==2048{save(dir,"rsa"+prefix+"-pkcs1.pem",pem.EncodeToMemory(&pem.Block{Type:"RSA PRIVATE KEY",Bytes:x509.MarshalPKCS1PrivateKey(key)}))}
 cert:=x509.Certificate{SerialNumber:big.NewInt(int64(bits)),Subject:pkix.Name{CommonName:"synthetic.invalid"},NotBefore:time.Date(2026,1,1,0,0,0,0,time.UTC),NotAfter:time.Date(2030,1,1,0,0,0,0,time.UTC),KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},DNSNames:[]string{"synthetic.invalid","second.invalid"}}
 variants:=[]string{"valid"};if bits==2048{variants=[]string{"valid","badku","badeku","critical","absent","any"}}
 for _,variant:=range variants{
  c:=cert;c.SerialNumber=big.NewInt(int64(bits+len(variant)))
  switch variant{case"badku":c.KeyUsage=x509.KeyUsageKeyEncipherment;case"badeku":c.ExtKeyUsage=[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth};case"critical":c.ExtraExtensions=[]pkix.Extension{{Id:[]int{1,2,3,4},Critical:true,Value:[]byte{5,0}}};case"absent":c.KeyUsage=0;c.ExtKeyUsage=nil;case"any":c.ExtKeyUsage=[]x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
  der,e:=x509.CreateCertificate(rand.Reader,&c,&c,&key.PublicKey,key);if e!=nil{panic(e)}
  save(dir,"rsa"+prefix+"-"+variant+".pem",pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}))
 }
}}
