package testutil

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/tyler-smith/go-bip39"
)

func TestMnemonicToPrivateKey(t *testing.T) {
	// 니모닉 문구
	mnemonic := "gesture inject test cycle original hollow east ridge hen combine junk child baconzero hope comfort vacuum milk pitch cage oppose unhappy lunar seat"

	// 니모닉을 시드로 변환
	seed := bip39.NewSeed(mnemonic, "")

	// 시드로부터 개인 키 생성
	privateKey, _ := btcec.PrivKeyFromBytes(seed)

	// 개인 키 출력
	privateKeyHex := hex.EncodeToString(privateKey.Serialize())
	expectedPrivateKey := "674c7c05499356c559436d41382e8fabf20244aea2f7b4fc8c5afb28629cb072" // 예상되는 개인 키를 여기에 입력하세요
	fmt.Println("privateKeyHex: ", privateKeyHex)
	if privateKeyHex != expectedPrivateKey {
		t.Errorf("개인 키가 예상과 다릅니다. 얻은 값: %s, 예상 값: %s", privateKeyHex, expectedPrivateKey)
	}
} 