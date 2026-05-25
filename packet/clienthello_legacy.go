package packet

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const MaxLegacyFakeSNILen = 219

var (
	legacyClientHelloTemplateHex = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	legacyClientHelloTemplate    []byte

	legacyTemplateSNI = []byte("mci.ir")

	legacyClientHelloStatic1 []byte
	legacyClientHelloStatic3 []byte
	legacyClientHelloStatic4 []byte
)

func init() {
	var err error
	legacyClientHelloTemplate, err = hex.DecodeString(legacyClientHelloTemplateHex)
	if err != nil {
		panic("packet: failed to decode legacy ClientHello template hex: " + err.Error())
	}

	sniLen := len(legacyTemplateSNI)
	legacyClientHelloStatic1 = legacyClientHelloTemplate[:11]
	legacyClientHelloStatic3 = legacyClientHelloTemplate[76:120]
	legacyClientHelloStatic4 = legacyClientHelloTemplate[127+sniLen : 262+sniLen]
}

func BuildLegacyClientHelloRecord(serverName string) ([]byte, error) {
	if serverName == "" {
		return nil, fmt.Errorf("packet: empty server name")
	}
	targetSNI := []byte(serverName)
	if len(targetSNI) > MaxLegacyFakeSNILen {
		return nil, fmt.Errorf("packet: server name too long for legacy ClientHello (%d bytes; max %d)", len(targetSNI), MaxLegacyFakeSNILen)
	}

	rnd := make([]byte, 32)
	sessID := make([]byte, 32)
	keyShare := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		return nil, fmt.Errorf("packet: random: %w", err)
	}
	if _, err := rand.Read(sessID); err != nil {
		return nil, fmt.Errorf("packet: session id: %w", err)
	}
	if _, err := rand.Read(keyShare); err != nil {
		return nil, fmt.Errorf("packet: key share: %w", err)
	}

	return buildLegacyClientHelloRecordWith(rnd, sessID, targetSNI, keyShare), nil
}

func buildLegacyClientHelloRecordWith(rnd, sessID, targetSNI, keyShare []byte) []byte {
	sniLen := len(targetSNI)

	serverNameExt := make([]byte, 0, 2+2+1+2+sniLen)
	serverNameExt = appendUint16BE(serverNameExt, uint16(sniLen+5))
	serverNameExt = appendUint16BE(serverNameExt, uint16(sniLen+3))
	serverNameExt = append(serverNameExt, 0x00)
	serverNameExt = appendUint16BE(serverNameExt, uint16(sniLen))
	serverNameExt = append(serverNameExt, targetSNI...)

	paddingLen := MaxLegacyFakeSNILen - sniLen
	paddingExt := make([]byte, 0, 2+paddingLen)
	paddingExt = appendUint16BE(paddingExt, uint16(paddingLen))
	paddingExt = append(paddingExt, make([]byte, paddingLen)...)

	result := make([]byte, 0, len(legacyClientHelloTemplate))
	result = append(result, legacyClientHelloStatic1...)
	result = append(result, rnd...)
	result = append(result, 0x20)
	result = append(result, sessID...)
	result = append(result, legacyClientHelloStatic3...)
	result = append(result, serverNameExt...)
	result = append(result, legacyClientHelloStatic4...)
	result = append(result, keyShare...)
	result = append(result, 0x00, 0x15)
	result = append(result, paddingExt...)

	return result
}

func appendUint16BE(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}
