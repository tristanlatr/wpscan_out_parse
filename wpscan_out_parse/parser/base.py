from abc import ABC, abstractmethod

########### BASE CLASS FOR CLI AND JSON PARSERS ##########


class _Component(ABC):
    """Base abstract class for all WPScan JSON and CLI components"""

    def __init__(self, data, false_positives_strings, show_all_details):

        if not data:
            data = {}
        self.data = data
        self.false_positives_strings = (
            false_positives_strings if false_positives_strings else []
        )
        self.show_all_details = False
        if show_all_details:
            self.show_all_details = True

    def is_false_positive(self, string):
        """False Positive Detection"""
        if not self.false_positives_strings:
            return False
        for fp_string in self.false_positives_strings:
            if fp_string in string:
                return True
        return False

    @abstractmethod
    def get_infos(self):
        """Return the component informations as a list of strings.  """
        pass

    @abstractmethod
    def get_warnings(self):
        """Return the component warnings as a list of strings.  """
        pass

    @abstractmethod
    def get_alerts(self):
        """Return the component alerts as a list of strings.  """
        pass


class _Parser(_Component):
    """Common class for CLI and JSON parsers.  """

    def __init__(self, data, *args, **kwargs):

        super().__init__(data, *args, **kwargs)

    @abstractmethod
    def get_results(self):
        """Returns a dictionnary structure like:
        ```
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
        ```
        """
        pass

    def get_summary_line(self):
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
    def get_error(self):
        """ Return any error or None if no errors"""
        pass
