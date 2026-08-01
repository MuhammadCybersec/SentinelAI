from .oracle_detection import OracleDetection


class OracleEnum(OracleDetection):
    """
    Detection layer.

    Contains ONLY detection-related functionality.
    """

    self.waf_detector
    self.sqli_detector
    self.boolean_detector
    self.time_detector
