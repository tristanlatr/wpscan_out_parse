import unittest
from wpscan_out_parse import parse_results_from_string

class T(unittest.TestCase):
    
       def test_parser(self):
              # false positives
              out = open("test/output_files/wordpress_no_vuln.json").read()
              result=parse_results_from_string(out)
              self.assertEqual(0, len(result['alerts']))

              out = open("test/output_files/wordpress_one_vuln.json").read()
              result=parse_results_from_string(out)
              self.assertEqual(4, len(result['warnings']))

              out = open("test/output_files/wordpress_many_vuln.json").read()
              result=parse_results_from_string(out)
              self.assertEqual(1, len(result['alerts']))

              out = open("test/output_files/wordpress_no_vuln.txt").read()
              result=parse_results_from_string(out)
              self.assertEqual(0, len(result['alerts']))

              out = open("test/output_files/wordpress_one_warning.txt").read()
              result=parse_results_from_string(out)
              self.assertEqual(2, len(result['warnings']))

              out = open("test/output_files/wordpress_many_vuln.txt").read()
              result=parse_results_from_string(out)
              self.assertEqual(8, len(result['alerts']))
              
              out = open("test/output_files/wordpress_one_vuln.txt").read()
              result=parse_results_from_string(out)
              self.assertEqual(1, len(result['alerts']))

    #    def test_false_positives(self):
    #           pass

    #    def test_version_could_not_be_detected_warning(self): 
    #           pass

    #    def test_version_could_not_be_detected_false_positive_mgmt(self): 
    #           pass

    #    def test_oudated_plugin_or_theme_version_warning(self):
    #           pass

    #    def test_vulnerabilities(self):
    #           pass

    #    def test_insecure_wordpress_warning(self):
    #           pass

    #    def test_password_attack(self):
    #           pass

    #    def test_lots_of_enumeration(self):
    #           pass

    #    def test_ref_metasploit_cve_exploitdb(self):
    #           pass