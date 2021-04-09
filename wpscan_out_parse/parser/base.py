from abc import ABC, abstractmethod
from typing import Any, Dict, Sequence, Optional, Union
from wpscan_out_parse.parser.results import WPScanResults

########### BASE CLASS FOR CLI AND JSON PARSERS ##########


class Component(ABC):
    """Base abstract class for all WPScan JSON and CLI components"""

    def __init__(self, data: Dict[str, Any], 
                 false_positives_strings:Sequence[str], 
                 show_all_details:bool) -> None:

        if not data:
            data = {}
        self.data: Dict[str, Any] = data
        """
        Initial data. 
        """

        self.false_positives_strings:Sequence[str] = (
            false_positives_strings if false_positives_strings else []
        )
        self.show_all_details: bool = False
        if show_all_details:
            self.show_all_details = True

    def is_false_positive(self, string:str) -> bool:
        """False Positive Detection"""
        if not self.false_positives_strings:
            return False
        for fp_string in self.false_positives_strings:
            if fp_string in string:
                return True
        return False

    @abstractmethod
    def get_infos(self) -> Sequence[str]:
        """Return the component informations as a list of strings.  """
        pass

    @abstractmethod
    def get_warnings(self) -> Sequence[str]:
        """Return the component warnings as a list of strings.  """
        pass

    @abstractmethod
    def get_alerts(self) -> Sequence[str]:
        """Return the component alerts as a list of strings.  """
        pass


class Parser(Component):
    """Common class for CLI and JSON parsers.  """

    def __init__(self, data:Dict[str, Any], *args:Any, **kwargs:Any):

        super().__init__(data, *args, **kwargs)

    @abstractmethod
    def get_results(self) -> WPScanResults:
        """Returns a dictionnary structure like
        
        ::
        
            {
            'infos':[],
            'warnings':[],
            'alerts':[],
            'summary':{
                'table':[
                    {
                        'Component': None,
                        'Version': None,
                        'Version State': None,
                        'Vulnerabilities': None,
                        'Status': None
                    },
                    ...
                ],
                'line':'WPScan result summary: alerts={}, warnings={}, infos={}, error={}'
                },
            'error':None
            }
        
        """
        pass

    def get_summary_line(self) -> str:
        """Return the summary string in one line"""
        line = (
            "WPScan result summary: alerts={}, warnings={}, infos={}, error={}".format(
                len(self.get_alerts()),
                len(self.get_warnings()),
                len(self.get_infos()),
                "1" if self.get_error() else "0",
            )
        )
        return line

    @abstractmethod
    def get_error(self) -> Optional[str]:
        """ Return any error or None if no errors"""
        pass
