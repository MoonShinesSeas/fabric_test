package main

import (
	"fmt"
	"crypto/rand"
	"math/big"
	"io/ioutil"
	"server/util"
	bp "server/bulletproof/src"
	"encoding/json"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"bytes"
	"log"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"

	"github.com/ZZMarquis/gm/sm2"
)

type Electricity struct{
	ID 	   string `json:"id"`
	Price  int64  `json:"price"`
	Amount int    `json:"amount"`
}
type Asset struct {
	Name    string  `json:"name"`
	Balance float64 `json:"balance"`
}
type CiperBalance struct{
	Initiator string `json:"initiator"`
	Recipient string `json:"recipient"`
	Price     string `json:"price"`
}
/*
Initiator: Initiator pub
Recipient: Recipient pub
OrderNum: ordernum
VerifySign: verifysign
*/
type Identity struct{
	Initiator string `json:"initiator"`
	Recipient string `json:"recipient"`
	OrderNum  string `json:"ordernum"`
	VerifySign string `json:"verifysign"`
}
type Transaction struct{
	ID string `json:"id"`
	Ciper_Price string `json:"ciper_price"`
	Amount int `json:"amount"`
}

func main() {
	log.Println("============ application-golang starts ============")

	err := os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
	if err != nil {
		log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
	}

	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	if !wallet.Exists("appUser") {
		err = populateWallet(wallet)
		if err != nil {
			log.Fatalf("Failed to populate wallet contents: %v", err)
		}
	}

	ccpPath := filepath.Join(
		"..",
		"..",
		"fabric-samples",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"connection-org1.yaml",
	)

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "appUser"),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
	}

	contract := network.GetContract("basic")

	log.Println("---初始化账本---")
	log.Println("--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger")
	result, err := contract.SubmitTransaction("InitLedger")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---测试Hello函数---")
	log.Println("--> Submit Transaction: Hello, function return hello")
	result, err = contract.SubmitTransaction("Hello")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---测试SetPublicKey函数--Alice---")
	log.Println("--> Submit Transaction: SetPublicKey, creates new publickey with alice_pub_str for Alice")
	alice_pri_str,alice_pub_str,err:=util.MyGenerateKey()
	if err!=nil{
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	result, err = contract.SubmitTransaction("SetPublicKey","Alice",alice_pub_str)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))
	// decode alice_pub_str
	alice_pub_bytes:=base64ToPublicKey(alice_pub_str)
	var alice_pub *sm2.PublicKey
	if err:=json.Unmarshal(alice_pub_bytes,&alice_pub);err!=nil{
		log.Fatalf("Failed to decode private_key: %v", err)
	}
	log.Println("alice-pub-:",alice_pub)

	log.Println("---测试SetPublicKey函数--Bob---")
	log.Println("--> Submit Transaction: SetPublicKey, creates new publickey with bob_pub_str for Bob")
	bob_pri_str,bob_pub_str,err:=util.MyGenerateKey()
	if err!=nil{
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	result, err = contract.SubmitTransaction("SetPublicKey","Bob",bob_pub_str)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---测试GetPublicKey函数--Alice---")
	log.Println("--> Submit Transaction: GetPublicKey, function return Alice-publickey")
	result, err = contract.EvaluateTransaction("GetPublicKey","publickeyAlice")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---测试GetPublicKey函数--Bob---")
	log.Println("--> Submit Transaction: GetPublicKey, function return Bob-publickey")
	result, err = contract.EvaluateTransaction("GetPublicKey","publickeyBob")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	var bob_pub sm2.PublicKey
	if err := json.Unmarshal(result, &bob_pub); err != nil {
		log.Fatalf("Failed to Unmarshal PublicKey: %v", err)
	}

	log.Println("---测试获取所有Electricity---")
	log.Println("--> Submit Transaction: GetAllElectricity, function return []*Electricity")
	result, err = contract.EvaluateTransaction("GetAllElectricity")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("---测试获取Electricity---")
	log.Println("--> Submit Transaction: GetElectricity, function return *Electricity")
	result, err = contract.EvaluateTransaction("GetElectricity","10000")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	var electricity Electricity  
    if err := json.Unmarshal(result, &electricity); err != nil {  
	    log.Fatalf("Failed to unmarshal electricity data: %v", err)  
    }  
	log.Println(string(result))

	log.Println("---测试发起交易提案---")
	log.Println("--> InitiateTranscation, function return cipertext")
	// 使用bytes.Buffer来存储转换后的字节  
	var buf bytes.Buffer  
	// 将int64类型的num写入buffer中  
	if err := binary.Write(&buf, binary.BigEndian, electricity.Price); err != nil {   
		fmt.Errorf("binary.Write failed: %v", err)
	}  
	hexCiperText, err := util.InitiateTranscation(buf.Bytes(),&bob_pub)
	if err != nil {
		log.Fatalf("Failed to InitiateTranscation: %v", err)
	}
	log.Println("hexCiperText = ",hexCiperText)

	//controduct transcation submit
	log.Println("--> controduct transcation")
	transaction:=Transaction{
		ID: electricity.ID,
		Ciper_Price: hexCiperText,
		Amount: electricity.Amount,
	}
	transaction_bytes,err:=json.Marshal(transaction)
	if err!=nil{
		log.Fatalf("Failed to Marshal transaction: %v", err)
	}
	log.Println(string(transaction_bytes))

	// send transcation => Bob
	log.Println("---测试确认交易提案---")
	log.Println("--> VerifyTranscation, function return verify")
	verify_res,err:=util.VerifyTranscation(hexCiperText,bob_pri_str,electricity.Price)
	if err != nil {
		log.Fatalf("Failed to VerifyTranscation: %v", err)
	}
	log.Println(verify_res)

	log.Println("---获取公钥环---")
	log.Println("--> GetRingPublicKeys, function return pubs")
	pubs,err:=contract.EvaluateTransaction("GetRingPublicKeys")
	if err != nil {
		log.Fatalf("Failed to VerifyTranscation: %v", err)
	}
	// decode crypto-key
	alice_pri_bytes:=base64ToPrivateKey(alice_pri_str)
	var alice_pri *sm2.PrivateKey
	if err:=json.Unmarshal(alice_pri_bytes,&alice_pri);err!=nil{
		log.Fatalf("Failed to decode private_key: %v", err)
	}
	log.Println("alice-pri:",alice_pri)

	bob_pri_bytes:=base64ToPrivateKey(bob_pri_str)
	var bob_pri *sm2.PrivateKey
	if err:=json.Unmarshal(bob_pri_bytes,&bob_pri);err!=nil{
		log.Fatalf("Failed to decode private_key: %v", err)
	}
	log.Println("bob-pri:",bob_pri)

	var ring_pubs []*sm2.PublicKey
	if err:=json.Unmarshal(pubs,&ring_pubs);err!=nil{
		log.Fatalf("Failed to decode publickeys: %v", err)
	}
	for i,v:=range ring_pubs{
		log.Println("pub-",i,"-:",v)
	}
	// sign
	log.Println("---签名---")
	log.Println("--> GenerateSign, function return string(sign)")
	sign,err:=util.GenerateSign(ring_pubs,bob_pri,transaction_bytes)
	if err != nil {
		log.Fatalf("Failed to GenerateSign: %v", err)
	}
	log.Println("sign:",sign)

	// verify
	log.Println("---验证---")
	log.Println("--> Submit Transaction: Verify, function return bool")
	s:=util.DecodeSignature(sign)
	verify := util.Verify(ring_pubs,transaction_bytes,s)
	log.Println("verify:",verify)

	// link ring_sign
	/*
	ring_pub: pubs
	sign1: {Bob price_cipertext,Alice balance,Price}
	{sign1,sign2}-->CA
	*/
	// alice encrypt balance
	log.Println("---alice encrypt balance---")
	result, err = contract.EvaluateTransaction("GetAssest","Alice")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	var alice Asset
	if err:=json.Unmarshal(result,&alice);err!=nil{
		log.Fatal("unmarshal alice error:%v",err)
	}
	alice_balance_cipertext,err:=encryptBalance((int64(alice.Balance)),alice_pub)
	if err!=nil{
		log.Fatal(err)
	}
	log.Println(string(alice_balance_cipertext))
	// alice encrypt price
	log.Println("---bob encrypt price---")
	alice_price_cipertext,err:=encryptBalance(electricity.Price,alice_pub)
	if err!=nil{
		log.Fatal(err)
	}
	log.Println(string(alice_price_cipertext))

	ciperBalance:=CiperBalance{
		Initiator: alice_balance_cipertext,
		Recipient: alice_price_cipertext,
		Price: hexCiperText,
	}
	ciperBalance_bytes,err:=json.Marshal(ciperBalance)
	if err!=nil{
		log.Fatal("marshal ciperBalance error:%v",err)
	}
	log.Println(string(ciperBalance_bytes))
	// alice comm price
	// comm,r:=bp.PedersenCommit(big.NewInt(electricity.Price))
	// log.Println("comm:",comm)
	// log.Println("---r:",r)
	// alice generate prove
	// prove:=bp.RangeProof(big.NewInt(electricity.Price))s
	bp.EC = bp.NewECPrimeGroupKey(8)
	prove:=bp.RPProve(big.NewInt(electricity.Price))
	log.Println("prove=",prove)
	/*
	pubs: ring_pub
    sign2: {Bob publickey,Alice Publickey,order number,sign}
	*/
	identity:=Identity{
		Initiator: alice_pub_str,
		Recipient: bob_pub_str,
		OrderNum: electricity.ID,
		VerifySign: sign,
	}
	identity_bytes,err:=json.Marshal(identity)
	if err!=nil{
		log.Fatal("marshal identity error:%v",err)
	}
	fmt.Println(string(identity_bytes))
	/*
	sign for ciperBalance_bytes,identity_bytes
	*/
	log.Println("---环签名---")
	baseSigner := util.NewBaseLinkableSigner(alice_pri, ring_pubs)
	sig1, err := baseSigner.Sign(rand.Reader, util.SimpleParticipantRandInt, ciperBalance_bytes)
	if err != nil {
		log.Fatal(err)
	}
	sig2, err := baseSigner.Sign(rand.Reader, util.SimpleParticipantRandInt, identity_bytes)
	if err != nil {
		log.Fatal(err)
	}
	if !baseSigner.Verify(ciperBalance_bytes, sig1) {
		log.Println("failed to verify the signature")
	}else{
		log.Println("sig1 verify")
	}
	if !baseSigner.Verify(identity_bytes, sig2) {
		log.Println("failed to verify the signature")
	}else{
		log.Println("sig1 verify")
	}
	if !util.Linkable(sig1, sig2) {
		log.Println("failed to link")
	}else{
		log.Println("link")
	}
	// verify prove
	if bp.RPVerify(prove) {
		log.Println("Range Proof Verification works")
	} else {
		log.Println("*****Range Proof FAILURE")
	}
	// verify success
	// two cipertext add
	alice_add_cipertext,err:=addBalance(alice_pub,alice_balance_cipertext,alice_price_cipertext)
	if err!=nil{
		log.Fatal(err)
	}
	log.Println("alice add cipertext=",string(alice_add_cipertext))
	//decrypt cipertext
	verify_plaintext,err:=util.VerifyCiperText(alice_pri_str,alice_add_cipertext)
	if err!=nil{
		log.Fatal(err)
	}
	log.Println("verify_plaintext=",verify_plaintext)
	log.Println("============ application-golang ends ============")
}
func base64ToPrivateKey(decodedBytes string) []byte {
	// 解码Base64字符串为原始字节
	privateKeyBytes, err := base64.StdEncoding.DecodeString(decodedBytes)
	if err != nil {
		panic(err)
	}
	// 现在privateKeyBytes就是Base64解码后的SM2私钥的[]byte格式
	return privateKeyBytes
}
func base64ToPublicKey(decodedBytes string) []byte {
	//编码Base64字符串为原始字节
	publicKeyBytes, err := base64.StdEncoding.DecodeString(decodedBytes)
	if err != nil {
		panic(err)
	}
	return publicKeyBytes
}
func populateWallet(wallet *gateway.Wallet) error {
	log.Println("============ Populating wallet ============")
	credPath := filepath.Join(
		"..",
		"..",
		"fabric-samples",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"users",
		"User1@org1.example.com",
		"msp",
	)

	// certPath := filepath.Join(credPath, "signcerts", "cert.pem")
	certPath := filepath.Join(credPath, "signcerts", "User1@org1.example.com-cert.pem")
	// read the certificate pem
	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return err
	}

	keyDir := filepath.Join(credPath, "keystore")
	// there's a single file in this dir containing the private key
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return fmt.Errorf("keystore folder should have contain one file")
	}
	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return err
	}

	identity := gateway.NewX509Identity("Org1MSP", string(cert), string(key))

	return wallet.Put("appUser", identity)
}

func encryptBalance(balance int64,pub *sm2.PublicKey)(string,error){
	// 使用bytes.Buffer来存储转换后的字节  
	var buf bytes.Buffer  
	// 将int64类型的num写入buffer中  
	if err := binary.Write(&buf, binary.BigEndian,balance); err != nil {   
		return "",err
	}
	// cipertext,err:=sm2.Encrypt(pub,buf.Bytes(),sm2.C1C2C3)
	plaintext:=buf.Bytes()
	cipertext,err:=util.HomoEncrypt(pub,plaintext)
	if err!=nil{
		return "",fmt.Errorf("encrypt balance error:%v",err)
	}
	hexCiperText := hex.EncodeToString(cipertext) 
	return hexCiperText,nil
}

func addBalance(pub *sm2.PublicKey,ciperText1 string,ciperText2 string)(string,error){
	hexCiperTextByte1,err:=hex.DecodeString(ciperText1)
	if err!=nil{
		return "",fmt.Errorf("failed to DecodeString: %v", err)
	}
	hexCiperTextByte2,err:=hex.DecodeString(ciperText2)
	if err!=nil{
		return "",fmt.Errorf("failed to DecodeString: %v", err)
	}
	cipertext,err:=util.CiperAdd(pub.Curve,hexCiperTextByte1,hexCiperTextByte2)
	if err!=nil{
		return "",fmt.Errorf("failed to CiperAdd: %v", err)
	}
	hexCiperText := hex.EncodeToString(cipertext) 
	return hexCiperText,nil
}