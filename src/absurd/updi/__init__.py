from .updiclient import (
	AddressStep,
	AddressWidth,
	DataWidth,
	UPDI_BASE_FEATURES,
    UPDI_DEFAULT_FEATURES,
	UnsupportedUpdiFeatureError,
	UpdiClient,
	UpdiException,
	UpdiFeatures,
	UpdiRev3,
)

KEY_NVMPROG = b'NVMProg '
KEY_NVMERASE = b'NVMErase'
KEY_NVMUSERROW = b'NVMUs&te'
KEY_OCD = b'OCD     '
