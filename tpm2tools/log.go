package tpm2tools

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/google/go-tpm/tpm2"
	"github.com/rekby/gpt"
)

const sha1HashSize = 20

// // HashAlgoToSize is a map converter for hash to length
// var HashAlgoToSize = map[tpm2.Algorithm]uint8{
// 	tpm2.AlgSHA1:   20,
// 	tpm2.AlgSHA256: 32,
// 	tpm2.AlgSHA384: 48,
// 	tpm2.AlgSHA512: 64,
// 	tpm2.AlgSM3:    32,
// }

// BIOSLogID is the legacy eventlog type
type BIOSLogID uint32

const (
	// EvPrebootCert see [2] specification in tcpa_log.go
	EvPrebootCert BIOSLogID = 0x0
	// EvPostCode see [2] specification in tcpa_log.go
	EvPostCode BIOSLogID = 0x1
	// EvUnused see [2] specification in tcpa_log.go
	EvUnused BIOSLogID = 0x2
	// EvNoAction see [2] specification in tcpa_log.go
	EvNoAction BIOSLogID = 0x3
	// EvSeparator see [2] specification in tcpa_log.go
	EvSeparator BIOSLogID = 0x4
	// EvAction see [2] specification in tcpa_log.go
	EvAction BIOSLogID = 0x5
	// EvEventTag see [2] specification in tcpa_log.go
	EvEventTag BIOSLogID = 0x6
	// EvSCRTMContents see [2] specification in tcpa_log.go
	EvSCRTMContents BIOSLogID = 0x7
	// EvSCRTMVersion see [2] specification in tcpa_log.go
	EvSCRTMVersion BIOSLogID = 0x8
	// EvCPUMicrocode see [2] specification in tcpa_log.go
	EvCPUMicrocode BIOSLogID = 0x9
	// EvPlatformConfigFlags see [2] specification in tcpa_log.go
	EvPlatformConfigFlags BIOSLogID = 0xA
	// EvTableOfServices see [2] specification in tcpa_log.go
	EvTableOfServices BIOSLogID = 0xB
	// EvCompactHash see [2] specification in tcpa_log.go
	EvCompactHash BIOSLogID = 0xC
	// EvIPL see [2] specification in tcpa_log.go
	EvIPL BIOSLogID = 0xD
	// EvIPLPartitionData see [2] specification in tcpa_log.go
	EvIPLPartitionData BIOSLogID = 0xE
	// EvNonHostCode see [2] specification in tcpa_log.go
	EvNonHostCode BIOSLogID = 0xF
	// EvNonHostConfig see [2] specification in tcpa_log.go
	EvNonHostConfig BIOSLogID = 0x10
	// EvNonHostInfo see [2] specification in tcpa_log.go
	EvNonHostInfo BIOSLogID = 0x11
	// EvOmitBootDeviceEvents see [2] specification in tcpa_log.go
	EvOmitBootDeviceEvents BIOSLogID = 0x12
)

// BIOSLogTypes are the BIOS eventlog types
var BIOSLogTypes = map[BIOSLogID]string{
	EvPrebootCert:          "EV_PREBOOT_CERT",
	EvPostCode:             "EV_POST_CODE",
	EvUnused:               "EV_UNUSED",
	EvNoAction:             "EV_NO_ACTION",
	EvSeparator:            "EV_SEPARATOR",
	EvAction:               "EV_ACTION",
	EvEventTag:             "EV_EVENT_TAG",
	EvSCRTMContents:        "EV_S_CRTM_CONTENTS",
	EvSCRTMVersion:         "EV_S_CRTM_VERSION",
	EvCPUMicrocode:         "EV_CPU_MICROCODE",
	EvPlatformConfigFlags:  "EV_PLATFORM_CONFIG_FLAGS",
	EvTableOfServices:      "EV_TABLE_OF_DEVICES",
	EvCompactHash:          "EV_COMPACT_HASH",
	EvIPL:                  "EV_IPL",
	EvIPLPartitionData:     "EV_IPL_PARTITION_DATA",
	EvNonHostCode:          "EV_NONHOST_CODE",
	EvNonHostConfig:        "EV_NONHOST_CONFIG",
	EvNonHostInfo:          "EV_NONHOST_INFO",
	EvOmitBootDeviceEvents: "EV_OMIT_BOOT_DEVICE_EVENTS",
}

// EFILogID is the EFI eventlog type
type EFILogID uint32

const (
	// EvEFIEventBase is the base value for all EFI platform
	EvEFIEventBase EFILogID = 0x80000000
	// EvEFIVariableDriverConfig see [1] specification in tcpa_log.go
	EvEFIVariableDriverConfig EFILogID = 0x80000001
	// EvEFIVariableBoot see [1] specification in tcpa_log.go
	EvEFIVariableBoot EFILogID = 0x80000002
	// EvEFIBootServicesApplication see [1] specification in tcpa_log.go
	EvEFIBootServicesApplication EFILogID = 0x80000003
	// EvEFIBootServicesDriver see [1] specification in tcpa_log.go
	EvEFIBootServicesDriver EFILogID = 0x80000004
	// EvEFIRuntimeServicesDriver see [1] specification in tcpa_log.go
	EvEFIRuntimeServicesDriver EFILogID = 0x80000005
	// EvEFIGPTEvent see [1] specification in tcpa_log.go
	EvEFIGPTEvent EFILogID = 0x80000006
	// EvEFIAction see [1] specification in tcpa_log.go
	EvEFIAction EFILogID = 0x80000007
	// EvEFIPlatformFirmwareBlob see [1] specification in tcpa_log.go
	EvEFIPlatformFirmwareBlob EFILogID = 0x80000008
	// EvEFIHandoffTables see [1] specification in tcpa_log.go
	EvEFIHandoffTables EFILogID = 0x80000009
	// EvEFIHCRTMEvent see [1] specification in tcpa_log.go
	EvEFIHCRTMEvent EFILogID = 0x80000010
	// EvEFIVariableAuthority see [1] specification in tcpa_log.go
	EvEFIVariableAuthority EFILogID = 0x800000E0
)

// EFILogTypes are the EFI eventlog types
var EFILogTypes = map[EFILogID]string{
	EvEFIEventBase:               "EV_EFI_EVENT_BASE",
	EvEFIVariableDriverConfig:    "EV_EFI_VARIABLE_DRIVER_CONFIG",
	EvEFIVariableBoot:            "EV_EFI_VARIABLE_BOOT",
	EvEFIBootServicesApplication: "EV_EFI_BOOT_SERVICES_APPLICATION",
	EvEFIBootServicesDriver:      "EV_EFI_BOOT_SERVICES_DRIVER",
	EvEFIRuntimeServicesDriver:   "EV_EFI_RUNTIME_SERVICES_DRIVER",
	EvEFIGPTEvent:                "EV_EFI_GPT_EVENT",
	EvEFIAction:                  "EV_EFI_ACTION",
	EvEFIPlatformFirmwareBlob:    "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	EvEFIHandoffTables:           "EV_EFI_HANDOFF_TABLES",
	EvEFIHCRTMEvent:              "EV_EFI_HCRTM_EVENT",
	EvEFIVariableAuthority:       "EV_EFI_VARIABLE_AUTHORITY",
}

// TCGAgileEventFormatID is the agile eventlog identifier for EV_NO_ACTION events
// const TCGAgileEventFormatID string = "Spec ID Event03"

// TCGOldEfiFormatID is the legacy eventlog identifier for EV_NO_ACTION events
const TCGOldEfiFormatID string = "Spec ID Event02"

// HCRTM string for event type EV_EFI_HCRTM_EVENT
// const HCRTM string = "HCRTM"

// [1] https://members.uefi.org/kws/documents/UEFI_Spec_2_7_A_Sept_6.pdf

// EFIGuid is the EFI Guid format
type EFIGuid struct {
	blockA uint32
	blockB uint16
	blockC uint16
	blockD uint16
	blockE [6]uint8
}

// EFIConfigurationTable is an internal UEFI structure see [1]
type EFIConfigurationTable struct {
	vendorGUID  EFIGuid
	vendorTable uint64
}

// EFIDevicePath is an internal UEFI structure see [1]
type EFIDevicePath struct {
	pathType    uint8
	pathSubType uint8
	length      [2]uint8
}

// TCGPCClientTaggedEvent is an legacy tag structure
type TCGPCClientTaggedEvent struct {
	taggedEventID       uint32
	taggedEventDataSize uint32
	taggedEventData     []byte
}

// EFIImageLoadEvent is an internal UEFI structure see [1]
type EFIImageLoadEvent struct {
	imageLocationInMemory uint64
	imageLengthInMemory   uint64
	imageLinkTimeAddress  uint64
	lengthOfDevicePath    uint64
	devicePath            []EFIDevicePath
}

// EFIGptData is the GPT structure
type EFIGptData struct {
	uefiPartitionHeader gpt.Header
	numberOfPartitions  uint64
	uefiPartitions      []gpt.Partition
}

// EFIHandoffTablePointers is an internal UEFI structure see [1]
type EFIHandoffTablePointers struct {
	numberOfTables uint64
	tableEntry     []EFIConfigurationTable
}

// EFIPlatformFirmwareBlob is an internal UEFI structure see [1]
type EFIPlatformFirmwareBlob struct {
	blobBase   uint64
	blobLength uint64
}

// EFIVariableData representing UEFI vars
type EFIVariableData struct {
	variableName       EFIGuid
	unicodeNameLength  uint64
	variableDataLength uint64
	unicodeName        []uint16
	variableData       []byte
}

// // IHA is a TPM2 structure
// type IHA struct {
// 	hash []byte
// }

// // THA is a TPM2 structure
// type THA struct {
// 	hashAlg tpm2.Algorithm
// 	digest  IHA
// }

// // LDigestValues is a TPM2 structure
// type LDigestValues struct {
// 	count   uint32
// 	digests []THA
// }

// // TcgEfiSpecIDEventAlgorithmSize is a TPM2 structure
// type TcgEfiSpecIDEventAlgorithmSize struct {
// 	algorithID uint16
// 	digestSize uint16
// }

// // TcgEfiSpecIDEvent is a TPM2 structure
// type TcgEfiSpecIDEvent struct {
// 	signature          [16]byte
// 	platformClass      uint32
// 	specVersionMinor   uint8
// 	specVersionMajor   uint8
// 	specErrata         uint8
// 	uintnSize          uint8
// 	numberOfAlgorithms uint32
// 	digestSizes        []TcgEfiSpecIDEventAlgorithmSize
// 	vendorInfoSize     uint8
// 	vendorInfo         []byte
// }

// TcgBiosSpecIDEvent is a TPM2 structure
type TcgBiosSpecIDEvent struct {
	signature        [16]byte
	platformClass    uint32
	specVersionMinor uint8
	specVersionMajor uint8
	specErrata       uint8
	uintnSize        uint8
	vendorInfoSize   uint8
	vendorInfo       []byte
}

// // TcgPcrEvent2 is a TPM2 default log structure (EFI only)
// type TcgPcrEvent2 struct {
// 	pcrIndex  uint32
// 	eventType uint32
// 	digests   LDigestValues
// 	eventSize uint32
// 	event     []byte
// }

// TcgPcrEvent is the TPM1.2 default log structure (BIOS, EFI compatible)
type TcgPcrEvent struct {
	pcrIndex  uint32
	eventType uint32
	digest    [20]byte
	eventSize uint32
	event     []byte
}

// PCRDigestValue is the hash and algorithm
type PCRDigestValue struct {
	DigestAlg tpm2.Algorithm
	Digest    []byte
}

// PCRDigestInfo is the info about the measurements
type PCRDigestInfo struct {
	PcrIndex     int
	PcrEventName string
	PcrEventData string
	Digests      []PCRDigestValue
}

// ParseLog extracts events the TPM2 Event log
func ParseLog(r io.Reader) (pcrList []PCRDigestInfo, err error) {
	var endianess binary.ByteOrder = binary.LittleEndian
	var pcrDigest PCRDigestInfo
	var pcrEvent TcgPcrEvent

	for {
		if err = binary.Read(r, endianess, &pcrEvent.pcrIndex); err == io.EOF {
			break
		} else if err != nil {
			return
		}
		if err = binary.Read(r, endianess, &pcrEvent.eventType); err == io.EOF {
			break
		} else if err != nil {
			return
		}
		if err = binary.Read(r, endianess, &pcrEvent.digest); err == io.EOF {
			break
		} else if err != nil {
			return
		}
		if err = binary.Read(r, endianess, &pcrEvent.eventSize); err == io.EOF {
			break
		} else if err != nil {
			return
		}

		if BIOSLogID(pcrEvent.eventType) == EvNoAction {
			pcrDigest.Digests = nil

			var biosSpecEvent TcgBiosSpecIDEvent
			if err = binary.Read(r, endianess, make([]byte, sha1HashSize)); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			if err = binary.Read(r, endianess, &pcrEvent.eventSize); err == io.EOF {
				break
			} else if err != nil {
				return
			}
			pcrEvent.event = make([]byte, pcrEvent.eventSize)

			if err = binary.Read(r, endianess, &biosSpecEvent.signature); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			identifier := string(bytes.Trim(biosSpecEvent.signature[:], "\x00"))
			if string(identifier) != TCGOldEfiFormatID {
				continue
			}

			if err = binary.Read(r, endianess, &biosSpecEvent.platformClass); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			if err = binary.Read(r, endianess, &biosSpecEvent.specVersionMinor); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			if err = binary.Read(r, endianess, &biosSpecEvent.specVersionMajor); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			if err = binary.Read(r, endianess, &biosSpecEvent.specErrata); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			if err = binary.Read(r, endianess, &biosSpecEvent.uintnSize); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			if err = binary.Read(r, endianess, &biosSpecEvent.vendorInfoSize); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			biosSpecEvent.vendorInfo = make([]byte, biosSpecEvent.vendorInfoSize)
			if err = binary.Read(r, endianess, &biosSpecEvent.vendorInfo); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			var in bytes.Buffer
			binary.Write(&in, endianess, biosSpecEvent)
			copy(pcrEvent.event, in.Bytes())

			if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
			}
			if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
			}
			pcrDigest.PcrEventData = string(pcrEvent.event)
		} else {
			// Placeholder
			pcrEvent.event = make([]byte, pcrEvent.eventSize)
			if err = binary.Read(r, endianess, &pcrEvent.event); err == io.EOF {
				break
			} else if err != nil {
				return
			}

			pcrDigest.Digests = make([]PCRDigestValue, 1)
			pcrDigest.Digests[0].DigestAlg = tpm2.AlgSHA1
			pcrDigest.Digests[0].Digest = pcrEvent.digest[:]

			if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
			}
			if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
			}

			eventDataString, _ := getEventDataString(pcrEvent.eventType, pcrEvent.event)
			if eventDataString != nil {
				pcrDigest.PcrEventData = *eventDataString
			}
		}

		pcrDigest.PcrIndex = int(pcrEvent.pcrIndex)
		pcrList = append(pcrList, pcrDigest)
	}
	return pcrList, nil
}

func getEventDataString(eventType uint32, eventData []byte) (*string, error) {
	if eventType < uint32(EvEFIEventBase) {
		switch BIOSLogID(eventType) {
		case EvSeparator:
			eventInfo := fmt.Sprintf("%x", eventData)
			return &eventInfo, nil
		case EvAction:
			eventInfo := string(bytes.Trim(eventData, "\x00"))
			return &eventInfo, nil
		case EvOmitBootDeviceEvents:
			eventInfo := string("BOOT ATTEMPTS OMITTED")
			return &eventInfo, nil
		case EvPostCode:
			eventInfo := string(bytes.Trim(eventData, "\x00"))
			return &eventInfo, nil
		case EvEventTag:
			eventInfo, err := getTaggedEvent(eventData)
			if err != nil {
				return nil, err
			}
			return eventInfo, nil
		case EvSCRTMContents:
			eventInfo := string(bytes.Trim(eventData, "\x00"))
			return &eventInfo, nil
		case EvIPL:
			eventInfo := string(bytes.Trim(eventData, "\x00"))
			return &eventInfo, nil
		}
	} else {
		switch EFILogID(eventType) {
		case EvEFIHCRTMEvent:
			eventInfo := "HCRTM"
			return &eventInfo, nil
		case EvEFIAction:
			eventInfo := string(bytes.Trim(eventData, "\x00"))
			return &eventInfo, nil
		case EvEFIVariableDriverConfig, EvEFIVariableBoot, EvEFIVariableAuthority:
			eventInfo, err := getVariableDataString(eventData)
			if err != nil {
				return nil, err
			}
			return eventInfo, nil
		case EvEFIRuntimeServicesDriver, EvEFIBootServicesDriver, EvEFIBootServicesApplication:
			eventInfo, err := getImageLoadEventString(eventData)
			if err != nil {
				return nil, err
			}
			return eventInfo, nil
		case EvEFIGPTEvent:
			eventInfo, err := getGPTEventString(eventData)
			if err != nil {
				return nil, err
			}
			return eventInfo, nil
		case EvEFIPlatformFirmwareBlob:
			eventInfo, err := getPlatformFirmwareBlob(eventData)
			if err != nil {
				return nil, err
			}
			return eventInfo, nil
		case EvEFIHandoffTables:
			eventInfo, err := getHandoffTablePointers(eventData)
			if err != nil {
				return nil, err
			}
			return eventInfo, nil
		}
	}

	eventInfo := string(bytes.Trim(eventData, "\x00"))
	return &eventInfo, errors.New("Event type couldn't get parsed")
}

func getVariableDataString(eventData []byte) (*string, error) {
	var eventReader = bytes.NewReader(eventData)
	var variableData EFIVariableData

	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.variableName.blockA); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.variableName.blockB); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.variableName.blockC); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.variableName.blockD); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.variableName.blockE); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.unicodeNameLength); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.variableDataLength); err != nil {
		return nil, err
	}

	variableData.unicodeName = make([]uint16, variableData.unicodeNameLength)
	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.unicodeName); err != nil {
		return nil, err
	}

	variableData.variableData = make([]byte, variableData.variableDataLength)
	if err := binary.Read(eventReader, binary.LittleEndian, &variableData.variableData); err != nil {
		return nil, err
	}

	guid := fmt.Sprintf("Variable - %x-%x-%x-%x-%x - ", variableData.variableName.blockA, variableData.variableName.blockB, variableData.variableName.blockC, variableData.variableName.blockD, variableData.variableName.blockE)
	eventInfo := guid
	utf16String := utf16.Decode(variableData.unicodeName)
	eventInfo += fmt.Sprintf("%s", string(utf16String))

	return &eventInfo, nil
}

func getImageLoadEventString(eventData []byte) (*string, error) {
	var eventReader = bytes.NewReader(eventData)
	var imageLoadEvent EFIImageLoadEvent

	if err := binary.Read(eventReader, binary.LittleEndian, &imageLoadEvent.imageLocationInMemory); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &imageLoadEvent.imageLengthInMemory); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &imageLoadEvent.imageLinkTimeAddress); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &imageLoadEvent.lengthOfDevicePath); err != nil {
		return nil, err
	}

	// Stop here we only want to know which device was used here.

	eventInfo := fmt.Sprintf("Image loaded at address 0x%d ", imageLoadEvent.imageLocationInMemory)
	eventInfo += fmt.Sprintf("with %db", imageLoadEvent.imageLengthInMemory)

	return &eventInfo, nil
}

func getHandoffTablePointers(eventData []byte) (*string, error) {
	var eventReader = bytes.NewReader(eventData)
	var handoffTablePointers EFIHandoffTablePointers

	if err := binary.Read(eventReader, binary.LittleEndian, &handoffTablePointers.numberOfTables); err != nil {
		return nil, err
	}

	handoffTablePointers.tableEntry = make([]EFIConfigurationTable, handoffTablePointers.numberOfTables)
	for i := uint64(0); i < handoffTablePointers.numberOfTables; i++ {
		if err := binary.Read(eventReader, binary.LittleEndian, &handoffTablePointers.tableEntry[i].vendorGUID.blockA); err != nil {
			return nil, err
		}

		if err := binary.Read(eventReader, binary.LittleEndian, &handoffTablePointers.tableEntry[i].vendorGUID.blockB); err != nil {
			return nil, err
		}

		if err := binary.Read(eventReader, binary.LittleEndian, &handoffTablePointers.tableEntry[i].vendorGUID.blockC); err != nil {
			return nil, err
		}

		if err := binary.Read(eventReader, binary.LittleEndian, &handoffTablePointers.tableEntry[i].vendorGUID.blockD); err != nil {
			return nil, err
		}

		if err := binary.Read(eventReader, binary.LittleEndian, &handoffTablePointers.tableEntry[i].vendorGUID.blockE); err != nil {
			return nil, err
		}

		if err := binary.Read(eventReader, binary.LittleEndian, &handoffTablePointers.tableEntry[i].vendorTable); err != nil {
			return nil, err
		}
	}

	eventInfo := fmt.Sprint("Tables: ")
	for _, table := range handoffTablePointers.tableEntry {
		guid := fmt.Sprintf("%x-%x-%x-%x-%x", table.vendorGUID.blockA, table.vendorGUID.blockB, table.vendorGUID.blockC, table.vendorGUID.blockD, table.vendorGUID.blockE)
		eventInfo += fmt.Sprintf("At address 0x%d with Guid %s", table.vendorTable, guid)
	}
	return &eventInfo, nil
}

func getPlatformFirmwareBlob(eventData []byte) (*string, error) {
	var eventReader = bytes.NewReader(eventData)
	var platformFirmwareBlob EFIPlatformFirmwareBlob

	if err := binary.Read(eventReader, binary.LittleEndian, &platformFirmwareBlob.blobBase); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &platformFirmwareBlob.blobLength); err != nil {
		return nil, err
	}

	eventInfo := fmt.Sprintf("Blob address - 0x%d - with size - %db", platformFirmwareBlob.blobBase, platformFirmwareBlob.blobLength)
	return &eventInfo, nil
}

func getGPTEventString(eventData []byte) (*string, error) {
	var eventReader = bytes.NewReader(eventData)
	var gptEvent EFIGptData

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.Signature); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.Revision); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.Size); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.CRC); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.HeaderStartLBA); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.HeaderCopyStartLBA); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.FirstUsableLBA); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.LastUsableLBA); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &gptEvent.uefiPartitionHeader.DiskGUID); err != nil {
		return nil, err
	}

	// Stop here we only want to know which device was used here.

	eventInfo := fmt.Sprint("Disk Guid - ")
	eventInfo += gptEvent.uefiPartitionHeader.DiskGUID.String()
	return &eventInfo, nil
}

func getTaggedEvent(eventData []byte) (*string, error) {
	var eventReader = bytes.NewReader(eventData)
	var taggedEvent TCGPCClientTaggedEvent

	if err := binary.Read(eventReader, binary.LittleEndian, &taggedEvent.taggedEventID); err != nil {
		return nil, err
	}

	if err := binary.Read(eventReader, binary.LittleEndian, &taggedEvent.taggedEventDataSize); err != nil {
		return nil, err
	}

	taggedEvent.taggedEventData = make([]byte, taggedEvent.taggedEventDataSize)
	if err := binary.Read(eventReader, binary.LittleEndian, &taggedEvent.taggedEventData); err != nil {
		return nil, err
	}

	eventInfo := fmt.Sprintf("Tag ID - %d - %s", taggedEvent.taggedEventID, string(taggedEvent.taggedEventData))
	return &eventInfo, nil
}
