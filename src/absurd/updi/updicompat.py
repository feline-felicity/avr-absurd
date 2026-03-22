from .updirev3 import UpdiClient, UPDI_REV1_FEATURES, UPDI_REV2_FEATURES, UPDI_REV4_FEATURES


class UpdiRev2(UpdiClient):
    def __init__(self, serialport:str, baudrate:int, updi_prescaler=0):
        super().__init__(serialport, baudrate, updi_prescaler=updi_prescaler, features=UPDI_REV2_FEATURES)


class UpdiRev4(UpdiRev2):
    def __init__(self, serialport:str, baudrate:int, updi_prescaler=0):
        UpdiClient.__init__(self, serialport, baudrate, updi_prescaler=updi_prescaler, features=UPDI_REV4_FEATURES)

class UpdiRev1(UpdiClient):
    def __init__(self, serialport:str, baudrate:int, updi_prescaler=0):
        super().__init__(serialport, baudrate, updi_prescaler=updi_prescaler, features=UPDI_REV1_FEATURES)
