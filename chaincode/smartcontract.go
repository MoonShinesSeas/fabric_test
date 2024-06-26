package chaincode

import (
	"strconv"
	"math/rand"

	"crypto/elliptic"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"time"
	"log"
	"math/big"
	"strings"
	
	"github.com/ZZMarquis/gm/sm2"
	"github.com/ZZMarquis/gm/sm3"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

type Asset struct {
	Name    string  `json:"name"`
	Balance float64 `json:"balance"`
}
type Bill struct{
	ID string `json:"id"`
	Transferor string `json:"transferor"`
	Amount float64 `json:"amount"`
	Collector string `json:"collector"`
}

type Electricity struct{
	ID string `json:"id"`
	Price int64 `json:"price"`
	Amount int `json:"amount"`
}
type Transaction struct{
	ID string `json:"id"`
	Ciper_Price string `json:"ciper_price"`
	Amount int `json:"amount"`
}
type UserInfo struct{
	ID string `json:"id"`
	Name string `json:"name"`
	PublicKey string `json:"publickey"`
}
func (s *SmartContract) Hello(ctx contractapi.TransactionContextInterface)(string){
	return "hello"
}
// InitLedger adds a base set of assets to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) (string,error) {
	names := [2]string{"Alice", "Bob"}
	balances := [2]float64{1000, 1000}
	ids :=[2]string{"10000","10001"}
	prices:=[2]int64{100,50}
	amounts:=[2]int{20,30}
	for i, v := range names {
		user := Asset{
			Name:    v,
			Balance: balances[i],
		}
		res, err := json.Marshal(user)
		if err != nil {
			return  "",err
		}
		if err := ctx.GetStub().PutState(v, []byte(res)); err != nil {
			return  "",err
		}
	}
	for i,v := range ids{
		electricity:=Electricity{
			ID:v,
			Price:prices[i],
			Amount:amounts[i],
		}
		res, err := json.Marshal(electricity)
		if err != nil {
			return  "",err
		}
		if err := ctx.GetStub().PutState(v, []byte(res)); err != nil {
			return  "",err
		}
	}
	return "",nil
}

func (s *SmartContract)GetAssest(ctx contractapi.TransactionContextInterface,name string)(*Asset,error){
	assestJSON, err := ctx.GetStub().GetState(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assestJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", name)
	}

	var asset Asset
	err = json.Unmarshal(assestJSON, &asset)
	if err != nil {
		return nil, err
	}
	return &asset, nil
}

func (s *SmartContract)GetAllElectricity(ctx contractapi.TransactionContextInterface)([]*Electricity, error){
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("10000", "11111")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var electricitys []*Electricity
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var electricity Electricity
		err = json.Unmarshal(queryResponse.Value, &electricity)
		if err != nil {
			return nil, err
		}
		electricitys = append(electricitys, &electricity)
	}
	return electricitys, nil
}

// GetElectricity returns the electricity stored in the world state with given id.
func (s *SmartContract)GetElectricity(ctx contractapi.TransactionContextInterface,id string)(*Electricity, error){
	electricityJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if electricityJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", id)
	}

	var electricity Electricity
	err = json.Unmarshal(electricityJSON, &electricity)
	if err != nil {
		return nil, err
	}
	return &electricity, nil
}
// /*
// value: publickey owner\accept Transcation
// Ids: Transcation object

// Error: endorsement failure during invoke. response: status:500 message:"Error handling success response. Value did not match schema:\n1. 
// return: Invalid type. Expected: array, given: string"
// */
// func (s *SmartContract)InitiateTranscation(ctx contractapi.TransactionContextInterface,value string,Ids string)(*Transaction,error){
// 	// 将加密后的字节切片转换为十六进制字符串  
// 	hexCiperPrice := hex.EncodeToString(ciper_price)  
// 	transaction:=Transaction{
// 		ID:electricity.ID,
// 		Ciper_Price:hexCiperPrice,
// 		Amount:electricity.Amount,
// 	}
// 	fmt.Println(transaction)
// 	if err != nil {
// 		return  nil,fmt.Errorf("failed to Marshal from transaction: %v", err)
// 	}
// 	return &transaction,nil
// }

func (s *SmartContract)SetPublicKey(ctx contractapi.TransactionContextInterface,name string,value string)(string,error){
	var pub sm2.PublicKey
	public_key_bytes:=base64ToPublicKey(value)
	if err := json.Unmarshal(public_key_bytes, &pub); err != nil {
		return "",err
	}
	flag:=sm2.GetSm2P256V1().IsOnCurve(pub.X,pub.Y)
	if !flag{
		return "the publickey is no invalid",nil
	}
	key:=fmt.Sprintf("publickey%s",name)
	if err:=ctx.GetStub().PutState(key,[]byte(value));err!=nil{
		return "put publickey failure",nil
	}
	return "success set publickey",nil
}

func (s *SmartContract) GetPublicKey(ctx contractapi.TransactionContextInterface, value string) (string,error) {
	public_key_base, err := ctx.GetStub().GetState(value)
	if err != nil {
		return "",err
	}
	public_key_bytes := base64ToPublicKey(string(public_key_base))
	if public_key_bytes == nil {
		return "public_key_bytes is nil",nil
	}
	var pub sm2.PublicKey
	if err := json.Unmarshal(public_key_bytes, &pub); err != nil {
		return "",err
	}
	return string(public_key_bytes),nil
}

func (s *SmartContract)GetRingPublicKeys(ctx contractapi.TransactionContextInterface)(string,error){
	resultsIterator, err := ctx.GetStub().GetStateByRange("publickey", "")
    if err != nil {
        return "", err
    }
    defer resultsIterator.Close()
    // Put all keys into a slice
    var keys []string
    for resultsIterator.HasNext() {
        res, err := resultsIterator.Next()
        if err != nil {
            return "", err
        }
        // Convert asset bytes to keys struct
		keys=append(keys,string(res.Value))
    }
	var random_pubs []string
	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())
	// Return the first five keys
	if len(keys) >= 5 {
		// Generate five random indices
		indices := generateRandomIndices(len(keys), 5)
		// Copy the keys at random indices to ring_pubs
		for _, index := range indices {
			random_pubs = append(random_pubs, keys[index])
		}
	} else {
		random_pubs = keys // If less than five keys, copy all keys to ring_pubs
	}
	var ring_pubs []*sm2.PublicKey
	for _,v:=range random_pubs{
		v_base:=base64ToPublicKey(v)
		var pub sm2.PublicKey
		if err:=json.Unmarshal(v_base,&pub);err!=nil{
			return "err",err
		}
		ring_pubs=append(ring_pubs,&pub)
	}
 	res_ring_bytes,err:=json.Marshal(ring_pubs)
 	if err!=nil{
		return "json marshal publickey error",err
 	}
    return string(res_ring_bytes), nil
}

// Function to generate 'n' unique random indices between 0 and 'max'
func generateRandomIndices(max, n int) []int {
    // Create a map to store unique indices
    indexMap := make(map[int]bool)
    for len(indexMap) < n {
        index := rand.Intn(max) // Generate a random index
        indexMap[index] = true  // Add the index to the map
    }

    // Convert map keys to slice
    indices := make([]int, 0, n)
    for index := range indexMap {
        indices = append(indices, index)
    }
    return indices
}
func (s *SmartContract)GetPublicKeys(ctx contractapi.TransactionContextInterface,value string)(string,error){
	res,err:=ctx.GetStub().GetState(value)
	if err!=nil{
		return "get publickeys error",err
	}
	res_bytes:=base64ToPublicKey(string(res))
	var pub []*sm2.PublicKey
	if err:=json.Unmarshal(res_bytes,&pub);err!=nil{
		return "json unmarshal publickey error",err
	}
	return string(res_bytes),nil
}
func (s *SmartContract)Verify(ctx contractapi.TransactionContextInterface,msg string,value string,pub_list string)(string,error){
	sign:=decodeSignature(value)
	var pub []*sm2.PublicKey
	public_key_bytes:=base64ToPublicKey(pub_list)
	if err := json.Unmarshal(public_key_bytes, &pub); err != nil {
		return "",err
	}
	if !ring_Verify(pub,[]byte(msg),sign){
		return "invalid",nil
	}
	return "valid",nil
}
// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}
	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
// 这个hash算法没有给出明确定义
func hash(pubs []*sm2.PublicKey, msg []byte, cx, cy *big.Int) *big.Int {
	h := sm3.New()  
	for _, pub := range pubs {  
		xBytes := pub.X.Bytes()  
		padXBytes := padToFixedLength(xBytes, 32) // 假设公钥的X和Y坐标需要填充到32字节  
		h.Write(padXBytes)  
		yBytes := pub.Y.Bytes()  
		padYBytes := padToFixedLength(yBytes, 32) // 假设公钥的X和Y坐标需要填充到32字节  
		h.Write(padYBytes)  
	}  
	h.Write(msg)  
	cxBytes := cx.Bytes()  
	padCXBytes := padToFixedLength(cxBytes, 32) // 假设cx和cy需要填充到32字节  
	h.Write(padCXBytes)  
	cyBytes := cy.Bytes()  
	padCYBytes := padToFixedLength(cyBytes, 32) // 假设cx和cy需要填充到32字节  
	h.Write(padCYBytes) 
	return hashToInt(h.Sum(nil), pubs[0].Curve) 
}
// padToFixedLength 将字节切片填充到固定长度。如果原始切片比目标长度短，则在前面填充0。
func padToFixedLength(slice []byte, length int) []byte {
	padded := make([]byte, length)
	copy(padded[length-len(slice):], slice)
	return padded
}
func ring_Verify(pubs []*sm2.PublicKey, msg []byte, signature []*big.Int) bool {
	if len(pubs)+1 != len(signature) {
		return false
	}
	c := new(big.Int).Set(signature[0])
	for i := 0; i < len(pubs); i++ {
		pub := pubs[i]
		s := signature[i+1]
		sx, sy := pub.Curve.ScalarBaseMult(s.Bytes())
		c.Add(s, c)
		c.Mod(c, pub.Curve.Params().N)
		cx, cy := pub.Curve.ScalarMult(pubs[i].X, pubs[i].Y, c.Bytes())
		cx, cy = pub.Curve.Add(sx, sy, cx, cy)
		c = hash(pubs, msg, cx, cy)
	}
	return c.Cmp(signature[0]) == 0
}
func decodeSignature(sign string) []*big.Int {
	// 在需要时，你可以将字符串解析为 []*big.Int 类型的环签名
	var parsedSignature []*big.Int
	if err := json.NewDecoder(strings.NewReader(sign)).Decode(&parsedSignature); err != nil {
		log.Fatal("JSON unmarshaling failed:", err)
	}
	return parsedSignature
}
// privateKeyToBase64 将PrivateKey结构体转换为Base64编码的字符串
func privateKeyToBase64(jsonBytes []byte) (string, error) {
	base64Str := base64.StdEncoding.EncodeToString(jsonBytes)
	return base64Str, nil
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

func publicKeyToBase64(jsonBytes []byte) (string, error) {
	base64Str := base64.StdEncoding.EncodeToString(jsonBytes)
	return base64Str, nil
}

func base64ToPublicKey(decodedBytes string) []byte {
	//编码Base64字符串为原始字节
	publicKeyBytes, err := base64.StdEncoding.DecodeString(decodedBytes)
	if err != nil {
		panic(err)
	}
	return publicKeyBytes
}

func flodSingature(signature []*big.Int) (string,error) {
	// 将环签名转换为 JSON 字符串
	signatureJSON, err := json.Marshal(signature)
	if err != nil {
		return "",err
	}
	// 将 JSON 字符串转换为普通字符串
	signatureString := string(signatureJSON)
	return signatureString,nil
}
func (s *SmartContract)Transfer(ctx contractapi.TransactionContextInterface,transferor string,amount string,collector string)(string,error){
	transferor_res_bytes,err:=ctx.GetStub().GetState(transferor)
	if err!=nil{
		return "",err
	}
	if len(transferor_res_bytes)==0{
		return "transferor is null",nil
	}
	var transferor_res_user Asset
	if err:=json.Unmarshal(transferor_res_bytes,&transferor_res_user);err!=nil{
		return "",err
	}
	collector_res_bytes,err:=ctx.GetStub().GetState(collector)
	if err!=nil{
		return "",err
	}
	if len(collector_res_bytes)==0{
		return "transferor is null",nil
	}
	var collector_res_user Asset
	if err:=json.Unmarshal(collector_res_bytes,&collector_res_user);err!=nil{
		return "",err
	}
	format_amount,err:=strconv.ParseFloat(amount,64)
	if err!=nil{
		return "",err
	}
	transferor_res_user.Balance=transferor_res_user.Balance-format_amount
	collector_res_user.Balance=collector_res_user.Balance+format_amount
	transferor_bytes,err:=json.Marshal(transferor_res_user)
	if err!=nil{
		return "",err
	}
	collector_bytes,err:=json.Marshal(collector_res_user)
	if err!=nil{
		return "",err
	}
	if err:=ctx.GetStub().PutState(transferor,transferor_bytes);err!=nil{
		return "",err
	}
	if err:=ctx.GetStub().PutState(collector,collector_bytes);err!=nil{
		return "",err
	}
	bill:=&Bill{
		ID:ctx.GetStub().GetTxID(),
		Transferor: transferor,
		Amount: format_amount,
		Collector: collector,
	}
	bill_bytes,err:=json.Marshal(bill)
	if err!=nil{
		return "marshal bill is error",err
	}
	if err:=ctx.GetStub().PutState(ctx.GetStub().GetTxID(),bill_bytes);err!=nil{
		return "put bill in stub error",err
	}
	return string(bill_bytes),nil
}