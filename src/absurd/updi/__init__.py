from .updirev3 import (
	AddressStep,
	AddressWidth,
	DataWidth,
	UPDI_REV1_FEATURES,
	UPDI_REV2_FEATURES,
	UPDI_REV3_FEATURES,
	UPDI_REV4_FEATURES,
	UnsupportedUpdiFeatureError,
	UpdiClient,
	UpdiException,
	UpdiFeatures,
	UpdiRev3,
)
from .updicompat import UpdiRev1, UpdiRev2, UpdiRev4

KEY_NVMPROG = b'NVMProg '
KEY_NVMERASE = b'NVMErase'
KEY_NVMUSERROW = b'NVMUs&te'
KEY_OCD = b'OCD     '
