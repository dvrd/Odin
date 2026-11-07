// Independent synthetic-key generator/verifier; no credentials or network.
package main
import (
 "crypto"
 "crypto/rand"
 "crypto/rsa"
 "crypto/sha256"
 "crypto/x509"
 "encoding/pem"
 "flag"
 "fmt"
 "os"
 "path/filepath"
)
func must(err error){if err!=nil {panic(err)}}
func main(){
 directory:=flag.String("dir",".","owned temporary fixture directory")
 verify:=flag.Bool("verify",false,"verify native signatures")
 flag.Parse()
 message:=[]byte("native RSA import interoperability\n")
 for _,bits:=range []int{1024,2048,4096}{
  stem:=filepath.Join(*directory,fmt.Sprintf("rsa%d",bits))
  if !*verify {
   key,err:=rsa.GenerateKey(rand.Reader,bits);must(err)
   der,err:=x509.MarshalPKCS8PrivateKey(key);must(err)
   public,err:=x509.MarshalPKIXPublicKey(&key.PublicKey);must(err)
   must(os.WriteFile(stem+".der",der,0600))
   must(os.WriteFile(stem+".pem",pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der}),0600))
   must(os.WriteFile(stem+".pub.pem",pem.EncodeToMemory(&pem.Block{Type:"PUBLIC KEY",Bytes:public}),0600))
  } else {
   der,err:=os.ReadFile(stem+".der");must(err)
   value,err:=x509.ParsePKCS8PrivateKey(der);must(err)
   key:=value.(*rsa.PrivateKey)
   digest:=sha256.Sum256(message)
   signature,err:=os.ReadFile(stem+".pkcs1.sig");must(err)
   must(rsa.VerifyPKCS1v15(&key.PublicKey,crypto.SHA256,digest[:],signature))
   signature,err=os.ReadFile(stem+".pss.sig");must(err)
   must(rsa.VerifyPSS(&key.PublicKey,crypto.SHA256,digest[:],signature,&rsa.PSSOptions{SaltLength:sha256.Size}))
  }
 }
 if !*verify {
  key,err:=rsa.GenerateMultiPrimeKey(rand.Reader,3,2048);must(err)
  der,err:=x509.MarshalPKCS8PrivateKey(key);must(err)
  must(os.WriteFile(filepath.Join(*directory,"multiprime.der"),der,0600))
 }
 must(os.WriteFile(filepath.Join(*directory,"message"),message,0600))
}
